use std::{
    borrow::Borrow,
    collections::BTreeMap,
    ops::{Bound, RangeBounds},
    sync::Arc,
};

/// An iterator over a range of key->values pairs in a `BiBTreeMap`.
pub(crate) struct KeyRange<'a, K: 'a, V: 'a> {
    inner: std::collections::btree_map::Range<'a, Arc<K>, Arc<V>>,
}

impl<'a, K: Ord, V> KeyRange<'a, K, V> {
    fn new(map: &'a BTreeMap<Arc<K>, Arc<V>>, range: (Bound<&'a K>, Bound<&'a K>)) -> Self {
        Self {
            inner: map.range::<K, (Bound<&K>, Bound<&K>)>(range),
        }
    }
}

impl<'a, K: Ord, V> Iterator for KeyRange<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| (k.as_ref(), v.as_ref()))
    }
}

impl<'a, K: Ord, V> DoubleEndedIterator for KeyRange<'a, K, V> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner
            .next_back()
            .map(|(k, v)| (k.as_ref(), v.as_ref()))
    }
}

/// A bimap backed by two `BTreeMap`.
pub(crate) struct BiBTreeMap<K, V> {
    /// A `BTreeMap` of `Arc` wrapped keys and values representing the key->value
    /// relationship.
    left2right: BTreeMap<Arc<K>, Arc<V>>,
    /// A `BTreeMap` of `Arc` wrapped keys and values representing the value->key
    /// relationship.
    right2left: BTreeMap<Arc<V>, Arc<K>>,
}

impl<K, V> BiBTreeMap<K, V>
where
    K: std::hash::Hash + Eq + Ord,
    V: std::hash::Hash + Eq + Ord,
{
    /// Crate an empty `BiBTreeMap`.
    pub(crate) fn new() -> Self {
        BiBTreeMap {
            left2right: BTreeMap::new(),
            right2left: BTreeMap::new(),
        }
    }

    /// Inserts the given key->value pair into the bimap.
    pub(crate) fn insert(&mut self, key: K, value: V) {
        let rc_key = Arc::new(key);
        let rc_value = Arc::new(value);
        self.right2left.insert(rc_value.clone(), rc_key.clone());
        self.left2right.insert(rc_key, rc_value);
    }

    /// Returns a reference to the value corresponding to the given key.
    pub(crate) fn get_by_left(&self, key: &K) -> Option<&V> {
        self.left2right.get(key).map(|x| x.as_ref())
    }

    /// Returns a reference to the key corresponding to the given value.
    pub(crate) fn get_by_right(&self, key: &V) -> Option<&K> {
        self.right2left.get(key).map(|x| x.as_ref())
    }

    /// Creates an iterator over the key->value pairs within a range of keys in the bimap in
    /// ascending order.
    pub(crate) fn range_by_left<'a, R>(&'a self, target: &'a R) -> KeyRange<'_, K, V>
    where
        Arc<K>: Borrow<K>,
        R: RangeBounds<K>,
    {
        let start = target.start_bound();
        let end = target.end_bound();
        KeyRange::new(&self.left2right, (start, end))
    }

    /// Returns the number of key->value pairs in the bimap.
    pub(crate) fn len(&self) -> usize {
        self.left2right.len()
    }
}

#[cfg(test)]
mod tests {
    use super::BiBTreeMap;
    use std::ops::Bound::{Included, Unbounded};

    fn bimap_init() -> BiBTreeMap<i32, i32> {
        let mut bimap = BiBTreeMap::new();
        bimap.insert(1, 2);
        bimap.insert(3, 4);
        bimap.insert(5, 6);
        bimap.insert(9, 10);

        bimap
    }

    #[test]
    fn insert() {
        let mut bimap = BiBTreeMap::new();
        assert!(bimap.len() == 0);

        bimap.insert(1, 2);
        assert!(bimap.len() == 1);
    }

    #[test]
    fn get_left() {
        let bimap = bimap_init();

        assert!(bimap.get_by_left(&1).unwrap() == &2);
        assert!(bimap.get_by_left(&3).unwrap() == &4);
        assert!(bimap.get_by_left(&5).unwrap() == &6);
    }

    #[test]
    fn get_right() {
        let bimap = bimap_init();

        assert!(bimap.get_by_right(&2).unwrap() == &1);
        assert!(bimap.get_by_right(&4).unwrap() == &3);
        assert!(bimap.get_by_right(&6).unwrap() == &5);
    }

    #[test]
    fn range_left() {
        let bimap = bimap_init();
        let bounding = (Unbounded, Included(7));
        let nearest = bimap.range_by_left(&bounding).next_back();

        assert!(nearest.unwrap() == (&5, &6));

        let nearest = bimap.range_by_left(&bounding).next();
        assert!(nearest.unwrap() == (&1, &2));
    }
}
