//! Persisted v1–v4 serialization, used only to verify digests during migration.
use libzond::rules::{CreateNew, Parameter, Requirement, Word};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Bound {
    Previous(PreviousBound),
    VersionFour(libzond::rules::BoundRule),
}

#[derive(Deserialize, Serialize)]
pub(super) struct PreviousBound {
    rule: Rule,
    home: String,
    cwd: PathBuf,
}

#[derive(Deserialize, Serialize)]
struct Rule {
    name: String,
    #[serde(default = "one", skip_serializing_if = "is_one")]
    language_version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    types: Vec<Type>,
    parameters: Vec<Parameter>,
    requirements: Vec<Requirement>,
    create_new: Option<CreateNew>,
    program: String,
    args: Vec<Word>,
    #[serde(default, skip_serializing_if = "is_false")]
    sudo_password: bool,
}
fn one() -> u32 {
    1
}
fn is_one(value: &u32) -> bool {
    *value == 1
}
fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Type {
    name: String,
    definition: Kind,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Kind {
    Alias {
        target: String,
    },
    Enum {
        values: Vec<String>,
    },
    Uint {
        #[serde(with = "decimal")]
        min: u64,
        #[serde(with = "decimal")]
        max: u64,
    },
    Int {
        #[serde(with = "decimal")]
        min: i64,
        #[serde(with = "decimal")]
        max: i64,
    },
    Integer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_inclusive: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_exclusive: Option<String>,
    },
    Text {
        pattern: String,
        min: usize,
        max: usize,
    },
    Choice {
        fields: Vec<String>,
        cases: BTreeMap<String, Vec<String>>,
    },
}

mod decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use std::{fmt::Display, str::FromStr};

    pub fn serialize<T: Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, T: FromStr + Display, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error>
    where
        T::Err: Display,
    {
        let text = String::deserialize(deserializer)?;
        let value = text.parse::<T>().map_err(D::Error::custom)?;
        if value.to_string() != text {
            return Err(D::Error::custom("noncanonical previous decimal bound"));
        }
        Ok(value)
    }
}
