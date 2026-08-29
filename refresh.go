package main

import (
	"net/http"
	"time"

	"chirpy/internal/auth"
)

// accessTokenExpiry is how long a minted JWT stays valid. Refresh tokens outlive
// it by a wide margin; their expiry lives in the database.
const accessTokenExpiry = time.Hour

const refreshTokenExpiry = 60 * 24 * time.Hour

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Token string `json:"token"`
	}

	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find refresh token", err)
		return
	}

	// The query filters out revoked and expired tokens, so a missing row covers
	// every reason the caller isn't entitled to a new access token.
	user, err := cfg.db.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't get user for refresh token", err)
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, accessTokenExpiry)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create JWT", err)
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		Token: token,
	})
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find refresh token", err)
		return
	}

	// An unknown token updates no rows and still reports success, which keeps the
	// endpoint from revealing which tokens exist.
	err = cfg.db.RevokeRefreshToken(r.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't revoke refresh token", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
