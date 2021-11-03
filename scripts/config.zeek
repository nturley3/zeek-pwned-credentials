##! Config for flow_intel module

## Determines whether to check just inbound traffic or also include outbound traffic.
## Set this to True if you only want to check traffic destined to your define local networks regardless of origin.
## Set this to false if you want to check traffic destined to any network regardless of origin.
## Recommend setting this to "T" to consume fewer resources for Zeek clusters, but "F" if running on a pcap file. 
const check_only_local_net_servers: bool = F;

## The name and path to the tab-deliminated file of pwned passwords.
## Adjust this to your Zeek environment.
## "pwned-passwords-sha1-reduced.intel" input file stucture:
#fields sha1hash    prevalence
const pwned_pwd_sha1_file = "/pcap/pwned-pass.txt" &redef;


## Uncomment for Corelight compatibility.
# const pwned_credentials::pwned_pwd_sha1_file = "pwned-passwords-sha1-reduced.intel";

## In a production environment, we recommend you set this to "F" for performance reasons.
## The http_request event will fire a lot, yet seldom are credentials submitted in the URI.
## Therefore, it probably isn't worth the performance impact to check the URI in a production environment.
const check_uri_for_credentials: bool = T;

## Writes to the log the value of the password field. 
## Most Zeek admins should keep this at False! 
## Not implemented.
# const  log_plaintext_password: bool = F;

## Writes to the log the value of the hashed password. 
## Most Zeek admins should keep this at False! 
## Not implemented.
# const  log_hashed_password: bool = F;