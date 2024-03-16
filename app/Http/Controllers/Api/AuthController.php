<?php

namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        if (auth()->attempt($request->all())) {
            return response([
                'user' => auth()->user(),
                'access_token' => auth()->user()->createToken('authToken')->accessToken
            ], Response::HTTP_OK);
        }

        return response([
            'message' => 'This User does not exist'
        ], Response::HTTP_UNAUTHORIZED);
    }

    public function register (Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:225',
            'email' => 'required|string|email|max:225|unique:users',
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ]);
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        return response($user, Response::HTTP_CREATED);
    }
}
