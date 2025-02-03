<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class JsonMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $content_json = trim($request->getContent());
        if ($content_json != '') {
            $content = json_decode($content_json);
            if (is_null($content)) {
                return abort(400, 'Malformed json input');
            }
        }

        return $next($request);
    }
}
