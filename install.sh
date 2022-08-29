#!/bin/bash

rename_cwd() {
  cd . || return
  new_dir=${PWD%/*}/$1
  mv -- "$PWD" "$new_dir" &&
    cd -- "$new_dir"
}
# Rename working folder to make calling the folder easier in python
rename_cwd advanced_report_reporting

# Add dependencies to poetry
sudo poetry add md2pdf tabulate stix2