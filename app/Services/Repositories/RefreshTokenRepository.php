<?php

namespace App\Services\Repositories;

use App\Models\RefreshToken;
use Carbon\Carbon;

class RefreshTokenRepository
{
    public function generateRefreshToken($user_id) : RefreshToken
    {
        $now = Carbon::now();
        $exp = $now->addSeconds(config('app.refresh_token_lifetime'));
        $token = hash( 'sha256', $user_id . '_' . $exp->getTimestamp() );
        RefreshToken::whereUserId($user_id)->delete();
        $refresh_token = new RefreshToken();
        $refresh_token->user_id = $user_id;
        $refresh_token->token = $token;
        $refresh_token->expires_at = $exp;
        $refresh_token->save();

        return $refresh_token;
    }

    public function authenticate($refresh_token) : RefreshToken | bool
    {
        $refresh_token = RefreshToken::whereToken($refresh_token)->first();
        if (is_null($refresh_token)) {
            return false;
        }

        $user_id = $refresh_token->user_id;
        $now = Carbon::now();
        $exp = $now->addSeconds(config('app.refresh_token_lifetime'));
        $token = hash('sha256', $user_id . '_' . $exp->getTimestamp());
        RefreshToken::whereUserId($user_id)->delete();
        $refresh_token = new RefreshToken();
        $refresh_token->user_id = $user_id;
        $refresh_token->token = $token;
        $refresh_token->expires_at = $exp;
        $refresh_token->save();

        return $refresh_token;
    }
}
