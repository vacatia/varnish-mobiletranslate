<?php
$jsonRules =  file_get_contents("https://raw.github.com/serbanghita/Mobile-Detect/master/Mobile_Detect.json");

$rules = json_decode($jsonRules);

function returnVarnishRules($rulesArray, $key, $useElse = false) {
    $retString = "\t\t";
    if ($useElse) {
        $retString .= "else if (\n";
    } else {
        $retString .= "if (\n";
    }
    $count = 0;
    foreach ($rulesArray as $rule) {
        $retString .= "\t\t";
        $retString .= "   (req.http.User-Agent ~ \"(?i)$rule\")";
        if ($count < (count((array)$rulesArray) -1)) {
            $retString .= " ||\n";
        } else {
            $retString .= ") {\n";
        }
        $count++;
    }
    $retString .= "\t\t\tset req.http.X-UA-Device = \"$key\";\n";
    $retString .= "\t\t}\n\n";

    return $retString;
}

$output[] = sprintf('# Copyright (c) 2014, Willem Kappers
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution. 
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies, 
# either expressed or implied, of the FreeBSD Project
# mobile_detect.vcl - Drop-in varnish solution to mobile user detection based on the Mobile-Detect library
#
# https://github.com/willemk/varnish-mobiletranslate
#
# Author: Willem Kappers
# Enhancements: Radu Topala <radu.topala@trisoft.ro>

sub devicedetect {
	#Based on Mobile detect %s
	
	#https://github.com/serbanghita/Mobile-Detect
	unset req.http.X-UA-Device;
	set req.http.X-UA-Device = "desktop";
	# Handle that a cookie may override the detection alltogether.
	if (req.http.Cookie ~ "(?i)X-UA-Device-force") {
		/* ;?? means zero or one ;, non-greedy to match the first. */
		set req.http.X-UA-Device = regsub(req.http.Cookie, "(?i).*X-UA-Device-force=([^;]+);??.*", "\1");
		/* Clean up our mess in the cookie header */
		set req.http.Cookie = regsuball(req.http.Cookie, "(^|; ) *X-UA-Device-force=[^;]+;? *", "\1");
		/* If the cookie header is now empty, or just whitespace, unset it. */
		if (req.http.Cookie ~ "^ *$") { unset req.http.Cookie; }
	} else {
', $rules->version);

$phones = $rules->uaMatch->phones;
$output[] = returnVarnishRules($phones, "phone");

$mobileBrowsers = $rules->uaMatch->browsers;
$output[] = returnVarnishRules($mobileBrowsers, "phone", true);

$mobileOS = $rules->uaMatch->os;
$output[] = returnVarnishRules($mobileOS, "phone", true);

$tablets = $rules->uaMatch->tablets;
$output[] = returnVarnishRules($tablets, "tablet");

$output[] = '   }
}
';

file_put_contents('mobile_detect.vcl', implode('', $output));
