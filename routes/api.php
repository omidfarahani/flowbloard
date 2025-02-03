<?php

use App\Http\Middleware\JsonMiddleware;
use Illuminate\Support\Facades\Route;

Route::middleware(JsonMiddleware::class)->namespace('App\Http\Controllers')->group(function() {
    Route::get('authenticate', 'AuthController@authenticate')->name('authenticate');
    Route::get('refresh_token', 'AuthController@refreshToken')->name('refresh_token');
});
