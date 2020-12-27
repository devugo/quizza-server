<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Laravel\Socialite\Facades\Socialite;

class UserController extends Controller
{
    /**
     * Authenticate users via form
     * 
     * @param array $data
     * @param \Illuminate\Http\Request  $request
     */
    public function authenticate($data = null, Request $request)
    {
        $credentials = $request->only('email', 'password');
        
        if($data){
            $credentials = $data;
        }

        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'invalid Credentials'], 400);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'Could not create Token'], 500);
        }

        $user = User::where('email', $credentials['email'])->first();

        return response()->json(compact('user', 'token'));
    }

    /**
     * Verify Google authenticated users
     * 
     * @param \Illuminate\Http\Request  $request
     */
    public function verify_google_auth(Request $request)
    {
        $token = $request->get('google_token');
        $id = $request->get('google_id');
        $user = Socialite::driver('google')->userFromToken($token);

        if($user->id === $id) {
            $this->allow_google_entry($user->email);

            return $this->authenticate(
                array(
                    'email' => $user->email,
                    'password' => 'password'
                ),
                $request
            );

            // return response()->json(['user' => $user]);
        }

        return response()->json('Unauthorized', 400);
    }

    /**
     * Allow user entry to app on login with Google
     * 
     * @param string $email
     */
    private function allow_google_entry($email)
    {
        // Check if user exists in the DB
        $user = User::where('email', $email)->first();

        if(!$user){
            User::create([
                'email' => $email,
                'username' => $email,
                'password' => Hash::make('password'),
                'name' => '',
                'role_id' => 2
            ]);
        }
    }

    public function register(Request $request)
    {
            $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'username' => 'required|string|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if($validator->fails()){
                return response()->json($validator->errors()->toJson(), 400);
        }

        $user = User::create([
            'name' => $request->get('name'),
            'email' => $request->get('email'),
            'username' => $request->get('username'),
            'password' => Hash::make($request->get('password')),
            'role_id' => 2
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json(compact('user','token'),201);
    }

    /**
     * Get Authenticated user from token
     */
    public function getAuthenticatedUser()
        {
            try {
                if (! $user = JWTAuth::parseToken()->authenticate()) {
                        return response()->json(['user_not_found'], 404);
                }

            } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

                    return response()->json(['token_expired'], $e->getStatusCode());

            } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

                    return response()->json(['token_invalid'], $e->getStatusCode());

            } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

                    return response()->json(['token_absent'], $e->getStatusCode());

            }

            return response()->json(compact('user'));
    }
}
