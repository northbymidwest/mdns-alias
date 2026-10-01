//! Sorting for the tiny lists here (a few addresses, records or types).
//! Insertion sort compiles to far less code than the standard library's
//! sorts, which are tuned for large inputs. Heapsort covers lists from the
//! network, which may be long, in a little more code.

/// Sorts `v` ascending, keeping equal elements in order. Quadratic, so only
/// for slices of our own that are known to be short, never for lists parsed
/// from the network.
pub fn sort<T: Ord>(v: &mut [T]) {
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && v[j - 1] > v[j] {
            v.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// Sorts `v` ascending in O(n log n) time with no allocation, so it is safe
/// for lists parsed from the network, unlike `sort`, which is quadratic and
/// only for our own tiny lists. Not stable.
pub fn heapsort<T: Ord>(v: &mut [T]) {
    let n = v.len();
    // Build a max-heap, then move the largest to the end one at a time.
    for start in (0..n / 2).rev() {
        sift_down(v, start, n);
    }
    for end in (1..n).rev() {
        v.swap(0, end);
        sift_down(v, 0, end);
    }
}

/// Restores the heap order below `root`, within `v[..end]`.
fn sift_down<T: Ord>(v: &mut [T], mut root: usize, end: usize) {
    loop {
        let mut child = 2 * root + 1;
        if child >= end {
            return;
        }
        if child + 1 < end && v[child] < v[child + 1] {
            child += 1;
        }
        if v[root] >= v[child] {
            return;
        }
        v.swap(root, child);
        root = child;
    }
}

#[cfg(test)]
mod tests {
    use super::{heapsort, sort};

    #[test]
    fn sorts_ascending() {
        let mut v = [3, 1, 2, 1, 5, 4];
        sort(&mut v);
        assert_eq!(v, [1, 1, 2, 3, 4, 5]);
        let mut e: [u8; 0] = [];
        sort(&mut e);
        let mut one = [7];
        sort(&mut one);
        assert_eq!(one, [7]);
    }

    fn check_heapsort<T: Ord + Clone + std::fmt::Debug>(v: &[T]) {
        let mut ours = v.to_vec();
        heapsort(&mut ours);
        let mut std = v.to_vec();
        std.sort();
        assert_eq!(ours, std);
    }

    #[test]
    fn heapsort_small_and_ordered_inputs() {
        check_heapsort::<u8>(&[]);
        check_heapsort(&[7]);
        check_heapsort(&[1, 2, 3, 4, 5, 6, 7, 8]);
        check_heapsort(&[8, 7, 6, 5, 4, 3, 2, 1]);
        check_heapsort(&[3, 1, 3, 2, 1, 3, 2, 2, 1]);
        check_heapsort(&[5, 5, 5, 5]);
    }

    #[test]
    fn heapsort_matches_the_standard_sort() {
        // A fixed xorshift sequence: varied lengths, values and duplicates.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..300 {
            let len = (next() % 64) as usize;
            let range = 1 + (round % 3) * 50;
            let v: Vec<u64> = (0..len).map(|_| next() % range).collect();
            check_heapsort(&v);
            let tuples: Vec<(u16, Vec<u8>)> = v
                .iter()
                .map(|&n| ((n % 7) as u16, vec![(n % 5) as u8; (n % 3) as usize]))
                .collect();
            check_heapsort(&tuples);
        }
    }
}
