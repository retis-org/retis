#define WS_BUILD_DLL

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/column.h>
#include <epan/column-info.h>

#include <wiretap/wtap.h>
#include <wiretap/pcapng_module.h>
#include <wiretap/wtap_opttypes.h>

#include <ws_symbol_export.h>
#include <ws_version.h>
#include <wsutil/wslog.h>

#include <json.h>

#define PLUGIN_VERSION "0.0.0"
#define RETIS_SCHEMA_BLOCK_TYPE 70000

/* Compatibility */
#define WIRESHARK_VERSION \
        ((WIRESHARK_VERSION_MAJOR * 100) + (WIRESHARK_VERSION_MINOR) * 10)

#if WIRESHARK_VERSION < 430
#error "Wireshark version 4.3 or higher is required"
#endif

/* Wireshark 4.6 changed the way to access custom options. */
#if WIRESHARK_VERSION >= 460
#define compat_wtap_opt_data(option) (option->custom_stringval.string)
#define compat_wtap_opt_len(option) (strlen(compat_wtap_opt_data(option)))
#define compat_wtap_opt_pen(option) (option->custom_stringval.pen)
#else
#define compat_wtap_opt_data(option) \
	(option->custom_opt.data.generic_data.custom_data)
#define compat_wtap_opt_len(option) \
	(option->custom_opt.data.generic_data.custom_data_len)
#define compat_wtap_opt_pen(option) (option->custom_opt.pen)
#endif

static int proto_retis = -1;
static json_object *schema = NULL;

static int ett_retis_base = -1; /* Base of retis tree types */
/* Dynamic field information */
struct retis_field_info {
	hf_register_info hfinfo;
	int id;
};

/* Static array of hf_register_info used for Wireshark field_info
 * registration */
static hf_register_info *retis_register_info;
/* Hashmap of json paths to struct retis_field_info */
static GHashTable *retis_field_info = NULL;
/* Hashmap of json paths to ETT IDs filled by Wireshark */
static GHashTable *retis_ett = NULL;
/* Static array of integers used for Wireshark ett registration */
static int **retis_register_ett;
/* Title of the root protocol item */
static const char *root_item_title;

/* Expert fields */
static expert_field ei_retis_schema_not_loaded = EI_INIT;
static expert_field ei_retis_json_parse_error = EI_INIT;
static expert_field ei_retis_payload_not_json_object = EI_INIT;
static expert_field ei_retis_schema_parse_error = EI_INIT;
static expert_field ei_retis_field_not_in_schema = EI_INIT;
static expert_field ei_retis_schema_block_empty = EI_INIT;

/* Whether columns have been reloaded yet. */
static bool cols_reloaded = false;

/* Forward declarations */
static int object_parse(json_object *props, const gchar *path, gchar **errstr);

static void free_retis_field_info(void *info_)
{
	struct retis_field_info *info = info_;
	g_free((char *)info->hfinfo.hfinfo.name);
	g_free((char *)info->hfinfo.hfinfo.abbrev);
	g_free(info);
}

static json_object *resolve_json_reference(json_object *obj)
{
	json_object *ref, *defs, *target;
	const char *ref_string;

	if (!schema || !obj || !json_object_is_type(obj, json_type_object)) {
		return NULL;
	}

	if (!json_object_object_get_ex(obj, "$ref", &ref) ||
	    !json_object_is_type(ref, json_type_string)) {
		return NULL;
	}

	ref_string = json_object_get_string(ref);
	if (strlen(ref_string) <= 8 || strncmp(ref_string, "#/$defs/", 8)) {
		ws_warning("failed to resolve reference, invalid ref: %s",
			   ref_string);
		return NULL;
	}
	ref_string += 8;

	if (!json_object_object_get_ex(schema, "$defs", &defs) ||
	    !json_object_is_type(defs, json_type_object)) {
		return NULL;
	}

	if (!json_object_object_get_ex(defs, ref_string, &target) ||
	    !json_object_is_type(target, json_type_object)) {
		return NULL;
	}

	return target;
}

static const char *definition_get_type(json_object *def)
{
	json_object *type;

	if (!json_object_object_get_ex(def, "type", &type)) {
		json_object *one_of = json_object_object_get(def, "oneOf");

		if (one_of && json_object_is_type(one_of, json_type_array) &&
		    json_object_array_length(one_of) > 1 &&
		    json_object_is_type(json_object_array_get_idx(one_of, 0),
					json_type_object)) {
			/* This is an object that can take different forms. */
			return "object";
		} else {
			ws_warning("Type definition not supported: %s",
				   json_object_to_json_string(def));
			return NULL;
		}
	}

	if (json_object_is_type(type, json_type_string)) {
		return json_object_get_string(type);
	} else if (json_object_is_type(type, json_type_array)) {
		if (!(json_object_array_length(type) == 2 &&
		      json_object_is_type(json_object_array_get_idx(type, 0),
					  json_type_string) &&
		      json_object_is_type(json_object_array_get_idx(type, 1),
					  json_type_string) &&
		      !strncmp(json_object_get_string(
				       json_object_array_get_idx(type, 1)),
			       "null", 4))) {
			ws_warning(
				"the only multi-type objects supported are nullable primitives: %s",
				json_object_to_json_string(def));
			return NULL;
		}
		return json_object_get_string(
			json_object_array_get_idx(type, 0));
	} else {
		ws_warning("type definition not supported: %s",
			   json_object_to_json_string(def));
		return NULL;
	}
}

static int definition_parse(json_object *def, const gchar *path, gchar *name,
			    gchar **errstr)
{
	struct retis_field_info *field_info;
	const gchar *type_str;
	json_object *ref;
	gchar *abbrev;

	ref = resolve_json_reference(def);
	if (ref) {
		return definition_parse(ref, path, name, errstr);
	}

	type_str = definition_get_type(def);
	if (!type_str) {
		*errstr = g_strdup_printf("malformed definition, no type: %s",
					  json_object_to_json_string(def));
		return -1;
	}

	abbrev = g_strdup_printf("retis.%s", path);

	field_info = g_malloc0(sizeof *field_info);
	field_info->id = -1; /* Will be populated by Wireshark. */
	field_info->hfinfo.p_id = &field_info->id;
	field_info->hfinfo.hfinfo.name = name;
	field_info->hfinfo.hfinfo.abbrev = abbrev;

	if (!strncmp(type_str, "string", 6)) {
		ws_info("proto registering key %s as string", path);
		field_info->hfinfo.hfinfo.type = FT_STRING;
		field_info->hfinfo.hfinfo.display = BASE_NONE;
		/* TODO: Add support for enums? */
	} else if (strcmp(type_str, "integer") == 0) {
		ws_info("proto registering key %s as integer", path);
		field_info->hfinfo.hfinfo.type = FT_UINT64;
		field_info->hfinfo.hfinfo.display = BASE_DEC;
	} else if (strcmp(type_str, "number") == 0) {
		ws_info("proto registering key %s as double", path);
		field_info->hfinfo.hfinfo.type = FT_DOUBLE;
		field_info->hfinfo.hfinfo.display = BASE_NONE;
	} else if (strcmp(type_str, "boolean") == 0) {
		ws_info("proto registering key %s as boolean", path);
		field_info->hfinfo.hfinfo.type = FT_BOOLEAN;
		field_info->hfinfo.hfinfo.display = BASE_NONE;
	} else if (strcmp(type_str, "array") == 0) {
		ws_info("proto registering key %s as array", path);
		field_info->hfinfo.hfinfo.type = FT_STRINGZ;
		field_info->hfinfo.hfinfo.display = BASE_NONE;
	} else if (!strncmp(type_str, "object", 6)) {
		int *p_ett_id, err;

		ws_info("proto registering key %s as object", path);
		field_info->hfinfo.hfinfo.type = FT_NONE;

		/* Create and store the pointer to where Wireshark will put the ETT ID */
		p_ett_id = g_malloc(sizeof(int));
		*p_ett_id = -1;

		g_hash_table_insert(retis_ett, g_strdup(path), p_ett_id);
		err = object_parse(def, path, errstr);
		if (err)
			return err;
	} else {
		g_free(field_info);
		*errstr = g_strdup_printf("unsupported type: %s: %s", type_str,
					  json_object_to_json_string(def));
		return -1;
	}

	g_hash_table_insert(retis_field_info, g_strdup(path), field_info);
	return 0;
}

/* Best-effort attept to generate a "name" for a type. */
char *definition_get_name(json_object *definition, const char *key)
{
	json_object *desc;
	char *name;

	if (json_object_object_get_ex(definition, "description", &desc) &&
	    json_object_get_string_len(desc)) {
		/* Get the first line without full stops. */
		const char *desc_str = json_object_get_string(desc);
		size_t off;

		for (off = 0; off < strlen(desc_str); off++) {
			if (desc_str[off] == '\n' || desc_str[off] == '\r' ||
			    desc_str[off] == '.')
				break;
		}
		name = g_malloc(off + 1);
		name[off] = '\0';
		memcpy(name, desc_str, off);
	} else {
		name = g_strdup(key);
	}
	return name;
}

static int object_properties_parse(json_object *props,
				   const gchar *current_path, gchar **errstr)
{
	if (!json_object_is_type(props, json_type_object)) {
		*errstr = g_strdup_printf("properties is not an object: %s",
					  json_object_to_json_string(props));
		return -1;
	}

	json_object_object_foreach(props, prop_key, prop_value)
	{
		json_object *any_of, *definition = NULL;
		gchar *prop_json_path;
		int err;

		prop_json_path = g_strdup_printf("%s%s%s", current_path,
			current_path[0] == '\0' ? "" : ".", prop_key);

		if (json_object_object_get_ex(prop_value, "anyOf", &any_of)) {
			for (size_t i = 0; i < json_object_array_length(any_of);
			     i++) {
				json_object *ref = resolve_json_reference(
					json_object_array_get_idx(any_of, i));
				if (ref) {
					// Do we need to cache parsed defs??
					definition = ref;
					break;
				}
			}
		} else {
			definition = prop_value;
		}

		if (!definition) {
			*errstr = g_strdup_printf(
				"definition not found on property %s",
				prop_key);
			err = -1;
			goto end;
		}
		err = definition_parse(
			definition, prop_json_path,
			definition_get_name(definition, prop_key), errstr);

end:
		g_free(prop_json_path);
		if (err)
			return err;
	}
	return 0;
}

static int object_parse(json_object *obj, const gchar *current_path,
			gchar **errstr)
{
	json_object *props, *one_of;

	if (!json_object_is_type(obj, json_type_object)) {
		*errstr = g_strdup_printf("type is not an object: %s",
					  json_object_to_json_string(obj));
		return -1;
	}

	if (json_object_object_get_ex(obj, "properties", &props)) {
		return object_properties_parse(props, current_path, errstr);
	} else if (json_object_object_get_ex(obj, "oneOf", &one_of)) {
		if (!json_object_is_type(one_of, json_type_array)) {
			*errstr = g_strdup_printf(
				"oneOf is not an array: %s",
				json_object_to_json_string(obj));
			return -1;
		}
		int err;
		for (size_t idx = 0; idx < json_object_array_length(one_of);
		     idx++) {
			err = object_parse(json_object_array_get_idx(one_of,
								     idx),
					   current_path, errstr);
			if (err)
				return err;
		}
	} else {
		*errstr = g_strdup_printf(
			"json-schema object does not contain 'properties' or 'oneOf': %s",
			json_object_to_json_string(obj));
		return -1;
	}
	return 0;
}

/* Looks at global schema and registers fields in Wireshark */
static int register_retis_fields_from_schema_json(tvbuff_t *tvb,
						  packet_info *pinfo,
						  proto_tree *tree)
{
	guint tvb_len = tvb ? tvb_reported_length(tvb) : 0;
	gchar *errstr = NULL;
	json_object *obj;
	int err;

	if (!schema || proto_retis == -1) {
		return -1;
	}

	retis_ett =
		g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	retis_field_info = g_hash_table_new_full(g_str_hash, g_str_equal,
						 g_free, free_retis_field_info);

	if (!retis_ett || !retis_field_info)
		return -1;

	if (!json_object_object_get_ex(schema, "title", &obj) ||
	    !json_object_is_type(obj, json_type_string)) {
		if (tree) {
			expert_add_info_format(
				pinfo,
				proto_tree_add_item(tree, proto_retis, tvb, 0,
						    tvb_len, ENC_NA),
				&ei_retis_schema_parse_error,
				"schema does not contain title");
		}
		return -1;
	}
	root_item_title = json_object_get_string(obj);

	if (!json_object_object_get_ex(schema, "properties", &obj) ||
	    !json_object_is_type(obj, json_type_object)) {
		if (tree) {
			expert_add_info_format(
				pinfo,
				proto_tree_add_item(tree, proto_retis, tvb, 0,
						    tvb_len, ENC_NA),
				&ei_retis_schema_parse_error,
				"schema does not contain properties");
		}
		return -1;
	}
	err = object_parse(schema, "", &errstr);
	if (err) {
		if (errstr && tree) {
			expert_add_info_format(
				pinfo,
				proto_tree_add_item(tree, proto_retis, tvb, 0,
						    tvb_len, ENC_NA),
				&ei_retis_schema_parse_error, "%s", errstr);
		}
		g_free(errstr);
		return err;
	}

	if (g_hash_table_size(retis_field_info)) {
		gpointer key, value;
		GHashTableIter iter;
		guint i = 0;

		retis_register_info = g_new(
			hf_register_info, g_hash_table_size(retis_field_info));

		g_hash_table_iter_init(&iter, retis_field_info);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			retis_register_info[i++] =
				((struct retis_field_info *)(value))->hfinfo;
		}

		proto_register_field_array(proto_retis, retis_register_info, i);
	} else {
		ws_warning("no fields in registered proto");
	}

	if (g_hash_table_size(retis_ett)) {
		gpointer key, value;
		GHashTableIter iter;
		guint i = 0;

		retis_register_ett = g_new(int *, g_hash_table_size(retis_ett));

		g_hash_table_iter_init(&iter, retis_ett);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			retis_register_ett[i++] = (int *)value;
		}

		proto_register_subtree_array(retis_register_ett, i);
	} else {
		ws_warning("no ETT in registered proto");
	}

	ws_info("protocol successfully registered");

	return 0;
}

static int dissect_retis_schema_custom_block(tvbuff_t *tvb, packet_info *pinfo,
					     proto_tree *tree, void *data _U_)
{
	guint tvb_len = tvb_reported_length(tvb);
	enum json_tokener_error error;
	const char *json_schema_str;

	if (schema) {
		/* Columns and their values are processed before the first
		 * dissector is called. This causes an issue if a column refers
		 * to fields that are not yet registered with the retis
		 * protocol. To avoid it, we rebuild the columns here. */
		if (pinfo->cinfo && !cols_reloaded) {
			int num_cols = pinfo->cinfo->num_cols;

			col_cleanup(pinfo->cinfo);
			build_column_format_array(pinfo->cinfo, num_cols,
						  false);
			cols_reloaded = true;
		}
		return tvb_captured_length(tvb); /* Consumed the block */
	}

	/* The tvb here contains the payload of the custom block. */
	if (tvb_len == 0) {
		if (tree) {
			expert_add_info(pinfo,
					proto_tree_add_item(tree, proto_retis,
							    tvb, 0, 0, ENC_NA),
					&ei_retis_schema_block_empty);
		}
		return 0;
	}

	// Get the block data as a string.
	// Use tvb_get_string_enc for safety, ensuring null termination for json_loads.
	json_schema_str = (const char *)tvb_get_string_enc(
		pinfo->pool, tvb, 0, tvb_len, ENC_UTF_8 | ENC_NA);
	if (!json_schema_str) {
		if (tree) {
			expert_add_info_format(
				pinfo,
				proto_tree_add_item(tree, proto_retis, tvb, 0,
						    tvb_len, ENC_NA),
				&ei_retis_schema_parse_error,
				"schema block data not valid UTF-8");
		}
		return tvb_captured_length(tvb);
	}

	schema = json_tokener_parse_verbose(json_schema_str, &error);

	if (!schema) {
		if (tree) {
			expert_add_info_format(
				pinfo,
				proto_tree_add_item(tree, proto_retis, tvb, 0,
						    tvb_len, ENC_NA),
				&ei_retis_schema_parse_error,
				"failed to parse retis schema from custom block: %d",
				error);
		}
		/*Even on error, we "consumed" the block's data from
		 * pcapng.block_type's perspective. */
		return tvb_captured_length(tvb);
	}

	/* Schema parsed successfully. Now register the dynamic fields. */
	if (register_retis_fields_from_schema_json(tvb, pinfo, tree)) {
		/* This is an internal error if parsing succeeded but */
		if (tree) {
			expert_add_info_format(
				pinfo,
				proto_tree_add_item(tree, proto_retis, tvb, 0,
						    tvb_len, ENC_NA),
				&ei_retis_schema_parse_error,
				"schema parsed but failed to register fields "
				"with epan");
		}
		json_object_put(schema);
		schema = NULL;
		return tvb_captured_length(tvb);
	}

	return tvb_captured_length(tvb);
}

static void populate_retis_subtree(proto_tree *tree, tvbuff_t *tvb,
				   json_object *event, const gchar *path)
{
	if (!json_object_is_type(event, json_type_object) || !tree)
		return;

	json_object_object_foreach(event, key, value)
	{
		struct retis_field_info *field_info;
		gchar *full_path = g_strdup_printf(
			"%s%s%s", path, path[0] == '\0' ? "" : ".", key);

		gpointer field_info_gptr =
			g_hash_table_lookup(retis_field_info, full_path);

		if (!field_info_gptr) {
			proto_tree_add_expert_format(
				tree, NULL, &ei_retis_field_not_in_schema, tvb,
				0, 0,
				"JSON data field '%s' not found in registered schema fields",
				full_path);
			g_free(full_path);
			continue;
		}
		field_info = (struct retis_field_info *)field_info_gptr;
		switch (json_object_get_type(value)) {
		case json_type_string:
			proto_tree_add_string(tree, field_info->id, NULL, 0, 0,
					      json_object_get_string(value));
			break;
		case json_type_int:
			proto_tree_add_uint64(tree, field_info->id, NULL, 0, 0,
					      json_object_get_uint64(value));
			break;
		case json_type_double:
			proto_tree_add_double(tree, field_info->id, NULL, 0, 0,
					      json_object_get_double(value));
			break;
		case json_type_boolean:
			proto_tree_add_boolean(tree, field_info->id, NULL, 0, 0,
					       json_object_get_boolean(value));
			break;
		case json_type_object: {
			gpointer ett_id_p_ptr =
				g_hash_table_lookup(retis_ett, full_path);
			if (ett_id_p_ptr) {
				int *ett_id_actual_ptr = (int *)ett_id_p_ptr;
				proto_item *sub_item = proto_tree_add_item(
					tree, field_info->id, NULL, 0, 0,
					ENC_NA);
				proto_tree *sub_tree = proto_item_add_subtree(
					sub_item, *ett_id_actual_ptr);
				populate_retis_subtree(sub_tree, tvb, value,
						       full_path);
			} else {
				proto_tree_add_expert_format(
					tree, NULL,
					&ei_retis_field_not_in_schema, tvb, 0,
					0,
					"JSON object data '%s' found, but no ETT (schema mismatch?)",
					full_path);
			}
			break;
		}
		case json_type_array: {
			const char *array_str = json_object_to_json_string_ext(
				value, JSON_C_TO_STRING_PLAIN);
			if (array_str) {
				proto_tree_add_string(tree, field_info->id,
						      NULL, 0, 0, array_str);
			}
			break;
		}
		case json_type_null:
			proto_tree_add_string(tree, field_info->id, NULL, 0, 0,
					      "(null)");
			break;
		default:
			break;
		}
		g_free(full_path);
	}
}

struct retis_option_foreach {
	tvbuff_t *tvb;
	packet_info *pinfo;
	proto_tree *tree;
};

static bool process_retis_option(wtap_block_t block _U_, unsigned option_id,
				 wtap_opttype_e option_type _U_,
				 wtap_optval_t *option, void *user_data)
{
	struct retis_option_foreach *user;
	json_object *retis_event;
	json_tokener *tok;
	bool ret;

	if (option_id != OPT_CUSTOM_STR_COPY ||
	    compat_wtap_opt_pen(option) != RETIS_SCHEMA_BLOCK_TYPE) {
		return true;
	}

	if (!schema) {
		return false;
	}

	user = (struct retis_option_foreach *)user_data;

	tok = json_tokener_new();
	retis_event = json_tokener_parse_ex(tok, compat_wtap_opt_data(option),
		compat_wtap_opt_len(option));

	if (!retis_event) {
		const char *err =
			json_tokener_error_desc(json_tokener_get_error(tok));
		if (user->tree) {
			expert_add_info_format(
				user->pinfo, proto_tree_get_root(user->tree),
				&ei_retis_json_parse_error,
				"custom EPB option JSON parse error: %s", err);
		}
		ret = false;
		goto parse_error;
	}
	if (!json_object_is_type(retis_event, json_type_object)) {
		if (user->tree) {
			expert_add_info(user->pinfo,
					proto_tree_get_root(user->tree),
					&ei_retis_payload_not_json_object);
		}
		ret = false;
		goto out;
	}
	if (user->tree) {
		proto_item *ti = proto_tree_add_protocol_format(
			user->tree, proto_retis, user->tvb, 0, 0,
			"%s", root_item_title);
		proto_tree *retis_main_tree =
			proto_item_add_subtree(ti, ett_retis_base);
		populate_retis_subtree(retis_main_tree, user->tvb, retis_event,
				       "");
	}
out:
	json_object_put(retis_event);
parse_error:
	json_tokener_free(tok);
	return ret;
}

static int dissect_retis_postdissector(tvbuff_t *tvb, packet_info *pinfo,
				       proto_tree *tree, void *data)
{
	if (!schema && pinfo) {
		if (pinfo)
			expert_add_info(pinfo, NULL,
					&ei_retis_schema_not_loaded);
		return 0;
	}

	if (!tree) {
		return 0;
	}

	struct retis_option_foreach opt_user_data;
	opt_user_data.tvb = tvb;
	opt_user_data.pinfo = pinfo;
	opt_user_data.tree = tree;

	wtap_block_foreach_option(pinfo->rec->block, process_retis_option,
				  (void *)&opt_user_data);
	return 0;
}

static void retis_cleanup()
{
	if (retis_field_info) {
		g_hash_table_destroy(retis_field_info);
		retis_field_info = NULL;
	}

	if (retis_ett) {
		g_hash_table_destroy(retis_ett);
		retis_ett = NULL;
	}

	if (retis_register_info) {
		g_free(retis_register_info);
		retis_register_info = NULL;
	}

	if (retis_register_ett) {
		g_free(retis_register_ett);
		retis_register_ett = NULL;
	}

	if (schema) {
		json_object_put(schema);
		schema = NULL;
	}
}

static void proto_register_retis(void)
{
	expert_module_t *expert_retis;

	if (proto_retis != -1) {
		return;
	}

	proto_retis = proto_register_protocol(
		"Retis (Dynamic Retis Event Metadata)", "Retis", "retis");

	static int *ett[] = { &ett_retis_base };
	proto_register_subtree_array(ett, array_length(ett));

	/* Expert items registration */
	expert_retis = expert_register_protocol(proto_retis);
	static ei_register_info ei[] = {
		{ &ei_retis_schema_not_loaded,
		  { "retis.schema.not_loaded", PI_UNDECODED, PI_WARN,
		    "retis schema not loaded from PCAPng file", EXPFILL } },
		{ &ei_retis_json_parse_error,
		  { "retis.json.parse_error", PI_MALFORMED, PI_WARN,
		    "retis JSON parsing from packet comment failed",
		    EXPFILL } },
		{ &ei_retis_payload_not_json_object,
		  { "retis.payload.not_object", PI_PROTOCOL, PI_WARN,
		    "retis payload in comment is not a JSON object",
		    EXPFILL } },
		{ &ei_retis_schema_parse_error,
		  { "retis.schema.parse_error", PI_MALFORMED, PI_WARN,
		    "retis schema JSON parsing from custom block failed",
		    EXPFILL } },
		{ &ei_retis_field_not_in_schema,
		  { "retis.field.not_in_schema", PI_PROTOCOL, PI_WARN,
		    "JSON field from comment not defined in loaded schema",
		    EXPFILL } },
		{ &ei_retis_schema_block_empty,
		  { "retis.schema.block_empty", PI_UNDECODED, PI_WARN,
		    "retis schema block is empty", EXPFILL } },
	};
	expert_register_field_array(expert_retis, ei, array_length(ei));
}

static void proto_reg_handoff_retis(void)
{
	static dissector_handle_t retis_postdissector_handle;
	static dissector_handle_t retis_schema_custom_block_handle;

	// Create handle for the post-dissector (for packet metadata)
	retis_postdissector_handle = create_dissector_handle(
		dissect_retis_postdissector, proto_retis);
	register_postdissector(retis_postdissector_handle);

	// Create handle for the custom PCAPng block dissector (for schema loading)
	retis_schema_custom_block_handle = create_dissector_handle(
		dissect_retis_schema_custom_block, proto_retis);
	dissector_add_uint("pcapng_custom_block", RETIS_SCHEMA_BLOCK_TYPE,
			   retis_schema_custom_block_handle);
}

/* Plugin versioning */
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

/* Standard plugin entry points */
WS_DLL_PUBLIC_DEF void plugin_register(void);
WS_DLL_PUBLIC_DEF void plugin_reg_handoff(void);

void plugin_register(void)
{
	static proto_plugin plug;

	plug.register_protoinfo = proto_register_retis;
	plug.register_handoff = proto_reg_handoff_retis;
	proto_register_plugin(&plug);
	register_cleanup_routine(&retis_cleanup);
}
