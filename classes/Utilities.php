<?php

namespace YaleREDCap\EntraIdEsignatures;

class Utilities
{
    public static function toLowerCase(string $string) : string {
        if (extension_loaded('mbstring')) {
            return mb_strtolower($string);
        }
        return strtolower($string);
    }
}