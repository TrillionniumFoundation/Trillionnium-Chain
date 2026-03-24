use super::*;

pub(crate) mod args {
    pub(crate) type Args = super::Args;
}

pub(crate) mod run {
    use super::*;

    pub(crate) fn run_node(args: Args) -> Result<()> {
        execute_runtime_loop(args)
    }
}
