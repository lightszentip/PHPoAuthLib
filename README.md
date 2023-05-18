PHPoAuthLib
===========
PHPoAuthLib provides oAuth support in PHP 7.2+ and is very easy to integrate with any project which requires an oAuth client.

see original code at https://github.com/daviddesberg/PHPoAuthLib and https://github.com/kingscode/PHPoAuthLib


[![Build Status](https://travis-ci.org/lightszentip/PHPoAuthLib.png?branch=master)](https://travis-ci.org/lightszentip/PHPoAuthLib)
[![Code Coverage](https://scrutinizer-ci.com/g/lightszentip/PHPoAuthLib/badges/coverage.png?s=a0a15bebfda49e79f9ce289b00c6dfebd18fc98e)](https://scrutinizer-ci.com/g/lightszentip/PHPoAuthLib/)
[![Scrutinizer Quality Score](https://scrutinizer-ci.com/g/lightszentip/PHPoAuthLib/badges/quality-score.png?s=c5976d2fefceb501f0d886c1a5bf087e69b44533)](https://scrutinizer-ci.com/g/lightszentip/PHPoAuthLib/)
[![Latest Stable Version](https://poser.pugx.org/lightszentip/oauth/v/stable.png)](https://packagist.org/packages/lightszentip/oauth)
[![Total Downloads](https://poser.pugx.org/lightszentip/oauth/downloads.png)](https://packagist.org/packages/lightszentip/oauth)

Installation
------------
This library can be found on [Packagist](https://packagist.org/packages/lightszentip/forked-oauth).
The recommended way to install this is through [composer](http://getcomposer.org).


```bash
    composer require lightszentip/forked-oauth
```

for more see https://github.com/daviddesberg/PHPoAuthLib/blob/master/README.md

Tests
------
```bash
    nerdctl run  -p 80:80 kennethreitz/httpbin
    #docker run  -p 80:80 kennethreitz/httpbin
    composer tests
```