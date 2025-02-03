<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class GenerateJwtKeys extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'jwt:generate-keys';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generates public and private key pair to be used in JWTs';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $private_key = openssl_pkey_new([
            "private_key_bits"  => 4096,
            "private_key_type"  => OPENSSL_KEYTYPE_RSA
        ]);
        $public_key_pem = openssl_pkey_get_details($private_key)['key'];
        openssl_pkey_export($private_key, $private_key_pem);

        file_put_contents( base_path('.jwt.public.key'), $public_key_pem );
        file_put_contents( base_path('.jwt.private.key'), $private_key_pem );

        $this->line('<fg=green>RSA key pair for JWT generated successfuly.</>');
    }
}
