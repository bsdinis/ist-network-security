use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    tonic_build::configure()
        .type_attribute(".", "#[derive(Serialize)]")
        .compile(
            &["./src/r2.proto"],
            &["./src/"]
        )?;

    tonic_build::compile_protos("./src/r2_identity.proto")?;
    Ok(())
}
