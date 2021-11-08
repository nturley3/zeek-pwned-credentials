
# Zeek-Credential

## Purpose

Checks detected passwords against the more prevalent haveibeenpwned passwords (see https://haveibeenpwned.com/Passwords).

## Installation/Upgrade

This script was written and tested using Zeek 3.0.11.

Use the Zeek package manager (zkg) to install and upgrade this module.

## Configuration

An intel file containing the SHA1 password hashes must be provided. Users can download the data file at https://haveibeenpwned.com/Passwords. 

Due to the large data set, we recommend downloading the dataset by prevalence then reducing the size of the dataset to a size the Zeek cluster can handle. We used a 500MB file size or the first 1,200,000 lines on an AP1000 Corelight sensor without trouble. The inability to utilize the entire pwned password database is a known issue.

Examine the scripts/config.zeek for configuration options.

An additional script logging the HTTP post body is required for examining post body data. See the zkg.meta file for suggestions or accept one (but not both!) of the suggested packages when using zkg to install.

An additional script is required for examing basic authentication credentials. See the zkg.meta file for a suggested package.

## Generated Outputs

A new field is added to the HTTP log to indicate if the password is in the loaded pwned dataset or not.

| Field Name | Data Type |  Description |
| ----- | ----- | ----- |
| pwned_password | `bool` | Identifies whether the detected password is in the haveibeenpwned password dataset. |
| username | `string` | The username detected in the supplied credentials. |

The module will also generate a notice log for each unique username.

## Usage

A security team can use the data collected in this module to help drive password policy changes, identify service accounts with weak passwords, or identify systems with users using weak passwords. This script may be helpful in identifying brute-force attempts.

Type: Hygiene

## About
Written by [@forewarned](https://github.com/forewarned), and [@JustinAzoff](https://github.com/JustinAzoff).
