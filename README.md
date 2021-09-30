
# Zeek-Credential

## Purpose

Checks detected passwords against the more prevalent haveibeenpwned passwords (see https://haveibeenpwned.com/Passwords).

## Installation/Upgrade

This script was written and tested using Zeek 3.0.11.

Use the Zeek package manager (zkg) to install and upgrade this module.

## Configuration

An intel file containing the SHA1 password hashes must be provided. Users can download the data file at https://haveibeenpwned.com/Passwords. It is highly recommended users download the file in order of prevalence. Due to the large dataset size, it is also recommended administrators reduce the data set down to a size the cluster can handle. (We tested this using a 500MB file size). The inability to utilize the entire pwned password database is a known issue.

## Generated Outputs

A new field is added to the HTTP log to indicate if the password is in the loaded pwned dataset or not.

| Field Name | Data Type |  Description |
| ----- | ----- | ----- |
| pwned_password | `bool` | Identified whether the detected password is in the haveibeenpwned password dataset. |
| username | `string` | The username detected in the supplied credentials. |

The module will also generate a notice log for each unique username.

## About
Written by [@forewarned](https://github.com/forewarned), and [@JustinAzoff](https://github.com/JustinAzoff).
