function Invoke-PhishStats() {
    # query phishstats API

    param([switch]$url, [switch]$title, [switch]$ip,
        $queryType = 'eq', $searchString)
    $baseUrl = 'https://phishstats.info:2096/api/phishing?_where'

    if ($url) { $field = 'url' }
    if ($title) { $field = 'title' }
    if ($ip) { $field = 'ip' }

    $query = "$baseUrl=($field, $queryType, $searchString)"
    $(Invoke-WebRequest $query).content | ConvertFrom-Json
}