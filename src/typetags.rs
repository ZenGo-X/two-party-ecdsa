use std::any::Any;

#[typetag::serde]
pub trait Value: Sync + Send + Any {
    fn as_any(&self) -> &dyn Any;
    fn type_name(&self) -> &str;
}

#[macro_export]
macro_rules! typetag_value {
    ($struct_name:ty) => {
        #[typetag::serde]
        impl Value for $struct_name {
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }

            fn type_name(&self) -> &str {
                stringify!($struct_name)
            }
        }

        impl std::fmt::Display for $struct_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
    };
}
