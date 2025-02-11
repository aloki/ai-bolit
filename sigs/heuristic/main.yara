// import "math"
include "webshells.yara"

/*private  global rule size_limit
{
    condition:
        filesize < 1MB
        
}

private rule is_php
{
    strings:
        $str = /<\?(php|\s)/

    condition:
        (filesize < 1MB) and $str
}

private rule php_keywords_rate {
    strings:
        $keyword = /\b(this|if|return|function|else|array|false|true)\b/
        
    condition:
        is_php and math.divide(#keyword, filesize) > 0.001
}

rule php_packed
{
    strings:
        $func1 = /base64_decode\s*\(/
        $func2 = /eval\s*\(/
        $func3 = /\$[a-zA-Z0-9_]+\(/
        
    condition:
        is_php and (($func1 and $func2) or $func3) and (math.entropy(0, filesize) >= 5.00)  and not php_keywords_rate //5.81
}
*./