use std::collections::HashMap;
use std::hash::Hash;

// The key space of `expected` is taken as the space of categories
pub fn chi_sq<T: Eq + Hash>(observed: HashMap<T, f64>, expected: HashMap<T, f64>) -> f64 {
    expected
        .iter()
        .fold(0f64, |a, (i, e)| {
            let &o = observed
                .get(&i)
                .unwrap_or(&0f64);
            a + (( (e - o).powi(2) ) / e)
        })
}

