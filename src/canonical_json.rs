//! Deterministic JSON encoding for provider request evidence.

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Serialize a value as compact JSON with recursively sorted object keys and
/// return that representation together with its lowercase SHA-256 digest.
pub(crate) fn canonical_json_and_sha256<T: Serialize>(
    value: &T,
) -> Result<(String, String), serde_json::Error> {
    let canonical_value = sort_object_keys(serde_json::to_value(value)?);
    let canonical_json = serde_json::to_string(&canonical_value)?;
    let sha256 = hex::encode(Sha256::digest(canonical_json.as_bytes()));
    Ok((canonical_json, sha256))
}

fn sort_object_keys(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));

            let mut sorted = Map::with_capacity(entries.len());
            for (key, value) in entries {
                sorted.insert(key, sort_object_keys(value));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_object_keys).collect()),
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::canonical_json_and_sha256;
    use serde::{Serialize, Serializer};
    use serde_json::json;

    #[derive(Serialize)]
    struct NestedLeft {
        z: u8,
        a: u8,
    }

    #[derive(Serialize)]
    struct OuterLeft {
        z: u8,
        nested: NestedLeft,
    }

    #[derive(Serialize)]
    struct NestedRight {
        a: u8,
        z: u8,
    }

    #[derive(Serialize)]
    struct OuterRight {
        nested: NestedRight,
        z: u8,
    }

    #[test]
    fn nested_object_order_does_not_change_canonical_output() {
        let left = OuterLeft {
            z: 3,
            nested: NestedLeft { z: 2, a: 1 },
        };
        let right = OuterRight {
            nested: NestedRight { a: 1, z: 2 },
            z: 3,
        };

        let left_output = canonical_json_and_sha256(&left).unwrap();
        let right_output = canonical_json_and_sha256(&right).unwrap();

        assert_eq!(left_output, right_output);
        assert_eq!(left_output.0, r#"{"nested":{"a":1,"z":2},"z":3}"#);
    }

    #[test]
    fn array_order_changes_canonical_output_and_hash() {
        let forward = canonical_json_and_sha256(&json!({"values": [1, 2, 3]})).unwrap();
        let reverse = canonical_json_and_sha256(&json!({"values": [3, 2, 1]})).unwrap();

        assert_ne!(forward.0, reverse.0);
        assert_ne!(forward.1, reverse.1);
    }

    #[test]
    fn canonical_json_is_compact_without_changing_scalar_values() {
        let (canonical, _) = canonical_json_and_sha256(&json!({
            "message": "spaces stay",
            "items": [true, null, 1.5]
        }))
        .unwrap();

        assert_eq!(
            canonical,
            r#"{"items":[true,null,1.5],"message":"spaces stay"}"#
        );
        assert!(!canonical.contains("\n"));
        assert!(!canonical.contains(": "));
        assert!(!canonical.contains(", "));
    }

    #[test]
    fn canonical_json_has_fixed_lowercase_sha256() {
        let (canonical, sha256) = canonical_json_and_sha256(&json!({"b": 2, "a": 1})).unwrap();

        assert_eq!(canonical, r#"{"a":1,"b":2}"#);
        assert_eq!(
            sha256,
            "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
    }

    struct SerializationFailure;

    impl Serialize for SerializationFailure {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(serde::ser::Error::custom(
                "intentional serialization failure",
            ))
        }
    }

    #[test]
    fn serialization_errors_are_returned() {
        let error = canonical_json_and_sha256(&SerializationFailure).unwrap_err();
        assert!(error
            .to_string()
            .contains("intentional serialization failure"));
    }
}
