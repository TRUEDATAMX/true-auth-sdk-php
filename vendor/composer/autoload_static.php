<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitebc2a88965fae3dc35f30e51eb378a2d
{
    public static $prefixLengthsPsr4 = array (
        'T' => 
        array (
            'Tdse\\TrueAuthSdkPhp\\' => 20,
        ),
        'F' => 
        array (
            'Firebase\\JWT\\' => 13,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Tdse\\TrueAuthSdkPhp\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
        'Firebase\\JWT\\' => 
        array (
            0 => __DIR__ . '/..' . '/firebase/php-jwt/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitebc2a88965fae3dc35f30e51eb378a2d::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitebc2a88965fae3dc35f30e51eb378a2d::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInitebc2a88965fae3dc35f30e51eb378a2d::$classMap;

        }, null, ClassLoader::class);
    }
}
