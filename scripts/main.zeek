# pwned_credentials

# "pwned-passwords-sha1-reduced.intel" input file stucture:
#fields sha1hash    prevalence

@load base/frameworks/notice

module pwned_credentials;


export
{
    redef enum Notice::Type += {
        ## Indicates this is a pwned-password notice
        PWNED_PASSWORD
        
    };
    
    # In the future we may also include the "prevalence" field.
    type pwned_pwd_sha1_idx: record {
        sha1hash: string;
    };

    global pwned_pwd_sha1_set: set[string] = set();

    # The record of the field value to be written out to the log.
    # Not implemented at this time.
    #type pwned_pwd_field: record {
        #username: string &optional &log; 
        #sha1_pwd: string &optional &log; 
    #} &redef;

    #const pwned_pwd_sha1_file = "/pcap/zeek_credential/pwned-passwords-sha1-reduced3.txt" &redef;
    const pwned_pwd_sha1_file = "/pcap/pwned-pass.txt" &redef;
    #const pwned_pwd_sha1_file = "/pcap/pwned-passwords-sha1.reduced3.txt" &redef;
    #const check_uri_for_credentials: bool = F;
    #const check_only_local_net_servers: bool = F;

    # We don't want to just find whenever the words appears, but we want to make sure it is a parameter.
    const username_sig: pattern = 
                    /username=/i | 
                    /user=/i | 
                    /userid=/i |
                    /log=/i # Wordpress username field
                    
                    &redef;

    # Didn't include an "=" because the pattern is checked as a key later in this script.
    const password_sig: pattern = 
                    /password/i | 
                    /pwd/i | 
                    /pass/i 
                    
                    &redef;

    const password_xml_sig: pattern = 
                    /\<password\>.+\<\/password\>/i |
                    /\<pwd\>.+\<\/pwd\>/i |
                    /\<pass\>.+\<\/pass\>/i

                    &redef;

    const password_xml_begin_sig: pattern = 
                    /\<password\>/i |
                    /\<pwd\>/i |
                    /\<pass\>/i

                    &redef;

    const password_xml_end_sig: pattern = 
                    /\<\/password\>/i |
                    /\<\/pwd\>/i |
                    /\<\/pass\>/i

                    &redef;
}

redef record HTTP::Info += {
	pwned_password: bool &log &optional;
};


event pwned_credentials::check_haveibeenpwned(c: connection, sha1hash: string)
{
    # The haveibeenpwned hashes are in uppercase. This function expects the hash to be passed in uppercase.
    # That's because we want as much work done on the workers as possible, and as little work done on the proxies.
    # FEATURE RELEASE TO DO:
    # Using K-anonimity could reduce the size of the input file. We may explore this further.
    if (sha1hash in pwned_pwd_sha1_set)
    {
        c$http$pwned_password = T;

        NOTICE([$note=PWNED_PASSWORD,
            $msg="A compromised password was used.",
            $sub=cat("Username: ", c$http$username),
            $conn=c,
            $identifier=c$http$username]);
    }
    else
    {
        c$http$pwned_password = F;
    }
}


function extract_credentials (http_parameters: string): table[string] of string
{
    local credential_table: table[string] of string;
    local vec_of_parameters: vector of string;
    vec_of_parameters = split_string(unescape_URI(http_parameters), /&/); 
    local key_value_pair: vector of string;

    for ( i in vec_of_parameters )
    {
        if ( username_sig in vec_of_parameters[i] )
        {
            key_value_pair = split_string(vec_of_parameters[i], /=/);
            if (|key_value_pair| >1)
            {
                credential_table["username"]=key_value_pair[1];
            }
        }
        if ( password_sig in vec_of_parameters[i] )
        {
            key_value_pair = split_string(vec_of_parameters[i], /=/);
            if (|key_value_pair| >1)
            {
                credential_table["password"]=key_value_pair[1];
            }
        }
    }
    return credential_table;
}


# This event will fire a lot, yet seldom are credentials submitted in the URI. For perfomance reasons this should be disabled by default.
# In an enterprise environment, if someone really wanted to check for creds in the URI a good SIEM/Logging solution will let them search for it themselves.
# To Do: Provide option to disable this check in the config file.
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    # See config.zeek for check_only_local_net_servers value.
    if (check_only_local_net_servers == T && Site::is_local_addr(c$id$resp_h) == F)
    {
        # Do this check 2nd for performance reasons because it's likely the check_uri_for_credentials will occur more frequently.
        if (check_uri_for_credentials == T && username_sig in unescaped_URI && password_sig in unescaped_URI)
        {
            return;
        }
        local credential_table: table[string] of string;
        credential_table=extract_credentials(unescaped_URI);
        if (credential_table["username"] != "")
        {
            c$http$username=credential_table["username"];
            if (credential_table["password"] != "")
            {
                @if (Cluster::is_enabled())
                    # Chose c$id$orig_h as the key over c$id$resp_h as it gives a more even distribution.
                    Cluster::publish_hrw(Cluster::proxy_pool, c$id$orig_h, pwned_credentials::check_haveibeenpwned, c, to_upper(sha1_hash(credential_table["password"])));
                @else
                    event pwned_credentials::check_haveibeenpwned(c, to_upper(sha1_hash(credential_table["password"])));
                @endif
            }
            else
            {
                # No need to check haveibeenpwned for blank passwords.
                c$http$pwned_password = T;
            }
        }
    }
}


# At this point we should have the basic_auth and post-body data to test against.
# There could be a scenario where a password is found in both basic_auth and the post_body. In
# this case the basic_auth should take precedence for this log. In the future we may consider writing out an array
# of usernames and pwn results.
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=10
{
    # See config.zeek for check_only_local_net_servers value.
    if(check_only_local_net_servers == T && Site::is_local_addr(c$id$resp_h) == F)
    {
        return;
    }
    # We only need to process credential submissions from the client
    if (is_orig == F)
    {
        return;
    }
    # The Basic Auth module will produce a password in the log that we can grab.
    if (c$http?$password)
    {
        @if (Cluster::is_enabled())
            # Chose c$id$orig_h as the key over c$id$resp_h as it gives a more even distribution.
            Cluster::publish_hrw(Cluster::proxy_pool, c$id$orig_h, pwned_credentials::check_haveibeenpwned, c, to_upper(sha1_hash(c$http$password)));
        @else
            event pwned_credentials::check_haveibeenpwned(c, to_upper(sha1_hash(c$http$password)));
        @endif
        return;
    }
    if (c$http?$post_body)
    {
        local vector_keys: vector of string;
        vector_keys = HTTP::extract_keys(c$http$post_body, /&/);
        # The HTTP::extract_keys function will return a vector of size 1 if there are no key-value pairs.
        # For efficiency sake, we can ignore a size 1 vector to skip processing regex over a large single-key.
        if (|vector_keys| > 1)
        {
            for (i in vector_keys)
            {
                if (password_sig in vector_keys[i])
                {
                    local credential_table: table[string] of string;
                    credential_table=extract_credentials(c$http$post_body);
                    # If we don't find a username, then we don't need to check for a password.
                    if (credential_table["username"] != "")
                    {
                        c$http$username=credential_table["username"];
                        if (credential_table["password"] != "")
                        {
                            @if (Cluster::is_enabled())
                                # Chose c$id$orig_h as the key over c$id$resp_h as it gives a more even distribution.
                                Cluster::publish_hrw(Cluster::proxy_pool, c$id$orig_h, pwned_credentials::check_haveibeenpwned, c, to_upper(sha1_hash(credential_table["password"])));
                            @else
                                event pwned_credentials::check_haveibeenpwned(c, to_upper(sha1_hash(credential_table["password"])));
                            @endif
                        }
                        else
                        {
                            #No need to check haveibeenpwned for blank passwords.
                            c$http$pwned_password = T;
                        }
                    }
                    return;
                }
            }
        }
        else
        {
            # To be implemented at a later time.
            # Check if password is in XML
            #if (password_xml_sig in c$http?$post_body)
            #{
            #    local pre_filter_password: vector[string] = split_string(s:c$http$post_body, re:password_xml_begin_sig);
            #    local post_filter_password: vector[string] = split_string(s:pre_filter_password[1], re:password_xml_end_sig);
            #    c$http$pwned_password=check_haveibeenpwned(post_filter_password[0]);
            #    return;
            #}
            #To Do: Check if Wordpress XML RPC
            #if (c$http?$uri)
            #{
            #    if (c$http?$uri=="/xmlrpc.php")
            #    {

            #    }
            #}
        }
    }
}


event zeek_init()
{
    # Because the haveibeenpwned data is so large, we want to only load it on proxies if available in a clustered environment.
    # 
    @if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY)
        Input::add_table([$source=pwned_pwd_sha1_file, $name="pwned_password_sha1",
                    $idx=pwned_pwd_sha1_idx, $destination=pwned_pwd_sha1_set,
                    $mode=Input::REREAD]);
        print "Intel loaded";
    @endif
    @if (!Cluster::is_enabled())
        Reporter::warning(fmt("A large pwned_password input file may cause performance impact on non-clustered Zeek systems."));
    @endif
}

