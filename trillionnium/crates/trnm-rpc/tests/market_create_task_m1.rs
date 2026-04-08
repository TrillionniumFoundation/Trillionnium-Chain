use std::fs;
use std::process::Command;

#[path = "market_create_task_m1/happy_path.rs"]
mod happy_path;
#[path = "market_create_task_m1/normalization.rs"]
mod normalization;
#[path = "market_create_task_m1/validation.rs"]
mod validation;
