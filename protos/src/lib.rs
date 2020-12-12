// We have streams, streams have non camel case type names :(
#![allow(non_camel_case_types)]

use serde::Serialize; // used in include_proto!

tonic::include_proto!("r2");
tonic::include_proto!("r2_identity");
