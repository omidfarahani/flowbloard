<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Services\Repositories\RefreshTokenRepository;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function authenticate(Request $request, RefreshTokenRepository $repo)
    {
        $request_content = json_decode($request->getContent());
        $email = $request_content->email ?? '';
        $password = $request_content->password ?? '';

        $user = User::whereEmail($email)->first();
        if ($user) {
            $private_key = file_get_contents(base_path('.jwt.private.key'));
            openssl_private_encrypt($email, $encrypted_email, $private_key);
            $check = Hash::check($password, $user->password);
            if ($check) {
                $payload = [
                    'iss'   => config('app.name'),
                    'iat'   => time(),
                    'exp'   => time() + config('app.access_token_lifetime'),
                    'usr'   => base64_encode($encrypted_email)
                ];
                $access_token = JWT::encode($payload, $private_key, 'RS256');

                $raw_refresh_token = $repo->generateRefreshToken($user->id);
                openssl_private_encrypt($raw_refresh_token->token, $encrypted_refresh_token, $private_key);
                $payload = [
                    'iss'       => env('APP_NAME'),
                    'iat'       => time(),
                    'exp'       => $raw_refresh_token->expires_at->getTimestamp(),
                    'usr'       => base64_encode($encrypted_refresh_token)
                ];
                $refresh_token = JWT::encode($payload, $private_key, 'RS256');

                return [
                    'access_token'  => $access_token,
                    'refresh_token' => $refresh_token,
                    'user'          => $user,
                ];
            }
        }

        return response('', 401);
    }

    public function refreshToken(Request $request, RefreshTokenRepository $repo)
    {
        $public_key = file_get_contents(base_path('.jwt.public.key'));
        $private_key = file_get_contents(base_path('.jwt.private.key'));
        $request_content = json_decode($request->getContent());
        if (!isset($request_content->refresh_token)) {
            return abort(401, 'No refresh token provided');
        }
        $refresh_token = $request_content->refresh_token;

        try {
            $payload = JWT::decode($refresh_token, new Key($public_key, 'RS256'));
        } catch (Exception $e) {
            return abort(401, 'Invalid refresh token');
        }

        $encrypted_refresh_token = base64_decode($payload->usr);
        openssl_public_decrypt($encrypted_refresh_token, $raw_refresh_token, $public_key);
        $new_refresh_token = $repo->authenticate($raw_refresh_token);

        if ($new_refresh_token) {
            $user = $new_refresh_token->user;

            openssl_private_encrypt($user->email, $encrypted_email, $private_key);
            $payload = [
                'iss'       => env('APP_NAME'),
                'iat'       => time(),
                'exp'       => time() + config('app.access_token_lifetime'),
                'usr'       => base64_encode($encrypted_email)
            ];
            $access_token = JWT::encode($payload, $private_key, 'RS256');

            openssl_private_encrypt($new_refresh_token->token, $encrypted_refresh_token, $private_key);
            $payload = [
                'iss'       => env('APP_NAME'),
                'iat'       => time(),
                'exp'       => $new_refresh_token->expires_at->getTimestamp(),
                'usr'       => base64_encode($encrypted_refresh_token)
            ];
            $refresh_token = JWT::encode($payload, $private_key, 'RS256');

            return [
                'access_token'  => $access_token,
                'refresh_token' => $refresh_token,
                'user'          => $user,
            ];
        } else {
            return abort(401, 'Invalid Refresh Token');
        }
    }
}
