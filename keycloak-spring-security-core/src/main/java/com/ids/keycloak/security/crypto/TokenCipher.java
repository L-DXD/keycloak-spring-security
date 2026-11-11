package com.ids.keycloak.security.crypto;

/**
 * 리프레시 토큰 암호화. KMS·HSM을 쓰려면 이 빈을 바꾼다.
 */
public interface TokenCipher {

    /** 활성 키로 암호화한다. */
    EncryptedToken encrypt(String plaintext);

    /**
     * 행에 적힌 키 id의 키로 푼다. 키를 바꾼 뒤에도 옛 행을 읽는다 (STORE-02).
     *
     * @throws TokenDecryptionException 모르는 키 id, 위조·손상 (STORE-03). 부른 쪽은 로컬 로그아웃으로 처리한다
     */
    String decrypt(EncryptedToken token);

    /** 이 암호문을 지금 활성 키로 다시 암호화해야 하는가 (키를 바꾼 뒤 다음 갱신 때). */
    boolean needsReEncryption(EncryptedToken token);
}
