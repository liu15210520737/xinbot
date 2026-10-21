/*
 * Copyright (C) 2024-2026 huangdihd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package xin.bbtt.mcbot.auth;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.auth.SessionService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.UUID;

/**
 * A {@link SessionService} that reports the join-server request to a
 * third-party Yggdrasil session server (外置登录) instead of Mojang's,
 * so servers behind authlib-injector can verify the bot's session.
 */
public class YggdrasilSessionService extends SessionService {

    private static final Gson gson = new Gson();
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();

    private final URI joinEndpoint;

    public YggdrasilSessionService(String authServer) {
        String base = authServer.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        this.joinEndpoint = URI.create(base + "/sessionserver/session/minecraft/join");
    }

    @Override
    public void joinServer(GameProfile profile, String authenticationToken, String serverId) throws IOException {
        UUID id = Objects.requireNonNull(profile.getId(), "GameProfile must have a UUID to join server");

        JsonObject payload = new JsonObject();
        payload.addProperty("accessToken", authenticationToken);
        payload.addProperty("selectedProfile", id.toString().replace("-", ""));
        payload.addProperty("serverId", serverId);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(joinEndpoint)
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(payload), StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while joining server", e);
        }

        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            String error = "HTTP " + response.statusCode();
            try {
                JsonObject body = gson.fromJson(response.body(), JsonObject.class);
                if (body != null && body.has("errorMessage")) {
                    error = body.get("errorMessage").getAsString();
                }
            } catch (Exception ignored) {
            }
            throw new IOException(error);
        }
    }
}
