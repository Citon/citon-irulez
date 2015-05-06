## xenapp-anon-request - Change regular Citrix XML requests to           ##
## anonymous - For use on LTM rules in front of Citrix XML service for   ##
## farm you want to use anonymous logins with.                           ##
## Make sure to use something out front in the F5 to authenticate with!  ##

## Author: Paul Hirsch <paul.hirsch at citon.com> 2015

# Strip username, password, and domain from Citrix XML requests and force
# to Anonymous
when CLIENT_ACCEPTED {
    log local0. "ENTER: CLIENT_ACCEPTED"
}

when SERVER_CONNECTED {
    log local0. "ENTER: SERVER_CONNECTED"
}

# Detect WebPN requests and collect up to the first 1000 bytes
when HTTP_REQUEST {
    log local0. "ENTER: HTTP_REQUEST"
    if { [HTTP::path] starts_with "/scripts/wpnbr.dll" } {
	# Get the content length so we can collect the data (to be processed 
	# in the HTTP_REQUEST_DATA event)
	# Limit collection to under 1Mb - See SOL6578 for details.
	if { [HTTP::header exists "Content-Length"] } {
	    if { [HTTP::header "Content-Length"] > 1048000 }{
		# Content-Length over 1Mb so collect 1Mb
		set content_length 1048000
	    } else {
		# Content-Length under 1Mb so collect actual length
		set content_length [HTTP::header "Content-Length"]
	    }
            log "citon-xenapp-anonymous: Request-Size: $content_length"
	} else {
	    # Response did not have Content-Length header, so use default of 1Mb
	    set content_length 1048000
	}

	# Don't collect content if Content-Length header value was 0
	if { $content_length > 0 } {
	    HTTP::collect $content_length
	}
    }
}

# Process collected request data and force passed credentials to anonymous
when HTTP_REQUEST_DATA {
    log local0. "ENTER: HTTP_REQUEST_DATA"

    set payload [HTTP::payload]

    # Look for <Credentials> tags and check range
    set sp [string first "<Credentials>" $payload]
    set ep [string first "</Credentials>" $payload]

    # Start and end found - Go to town
    if { { $sp > -1 } && { $ep > -1 } } {
	# Calculate starting point and length within <Credentials>
	set sp [$sp + 13]
	set len [$ep - $sp]

	# Replace everything with a simple AnonymousUser tag set
	HTTP::payload replace $sp $len "<AnonymousUser></AnonymousUser>"
    }
}
