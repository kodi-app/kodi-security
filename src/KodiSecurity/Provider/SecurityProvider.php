<?php
/**
 * Created by PhpStorm.
 * User: nagyatka
 * Date: 2017. 09. 23.
 * Time: 12:26
 */

namespace KodiSecurity\Provider;


use KodiSecurity\Model\SecurityManager;
use Pimple\Container;
use Pimple\ServiceProviderInterface;

class SecurityProvider implements ServiceProviderInterface
{
    private $configuration;

    /**
     * SecurityProvider constructor.
     * @param $configuration
     */
    public function __construct($configuration)
    {
        $this->configuration = $configuration;
    }


    public function register(Container $pimple)
    {
        $conf = $this->configuration;
        $pimple['security'] = $pimple->factory(function ($c) use($conf) {
            return new SecurityManager($conf);
        });
    }
}