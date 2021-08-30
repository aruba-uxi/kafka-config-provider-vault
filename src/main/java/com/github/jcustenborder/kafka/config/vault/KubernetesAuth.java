/**
 * Copyright © 2021 Jeremy Custenborder (jcustenborder@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.jcustenborder.kafka.config.vault;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.response.AuthResponse;
import com.google.common.base.Strings;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.io.IOException;

public class KubernetesAuth {
  VaultConfigProviderConfig config;
  Vault vault;

  public KubernetesAuth(VaultConfigProviderConfig config, Vault vault) {
    this.config = config;
    this.vault = vault;
  }

  private static String getJWT(String path) {
    String content = "";
    Path file = Paths.get(path);
    try {
      content = new String(Files.readAllBytes(file));
    } catch (IOException e) {
      e.printStackTrace();
    }
    return content;
  }

  public String getToken() {
    try {

      if (Strings.isNullOrEmpty(config.role)) {
        throw new Exception("ROLE is empty or undefined");
      }

      if (Strings.isNullOrEmpty(config.jwtPath)) {
        throw new Exception("JWT_PATH is empty or undefined");
      }

      String role = config.role;
      String jwt = getJWT(config.jwtPath);
      AuthResponse authResponse = vault.auth().loginByKubernetes(role, jwt);

      return authResponse.getAuthClientToken();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
