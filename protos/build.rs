use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    tonic_build::compile_protos("./src/r2.proto")?;
    tonic_build::compile_protos("./src/r2_identity.proto")?;
    Ok(())
}
