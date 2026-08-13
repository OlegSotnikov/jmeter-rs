// SPDX-License-Identifier: Apache-2.0

/*
 * Original, non-production lifecycle probe for PROXY-003.
 *
 * Invocation is deliberately explicit and bounded:
 *   MirrorServerHarness <port> 2 4 <hold-ms>
 * The probe owns the HttpMirrorServer it creates, never invokes a shell or
 * subprocess, and stops the server from a finally block.  It is not a
 * replacement for a production server and is not run during static corpus
 * authoring.
 */

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.apache.jmeter.protocol.http.control.HttpMirrorServer;

public final class MirrorServerHarness {
    private static final int MIN_UNPRIVILEGED_PORT = 1024;
    private static final int MAX_PORT = 65535;
    private static final int MANIFEST_POOL_SIZE = 2;
    private static final int MANIFEST_QUEUE_SIZE = 4;
    private static final int MAX_HOLD_MILLIS = 5000;
    private static final int STARTUP_TIMEOUT_MILLIS = 1500;
    private static final int READY_CONNECT_TIMEOUT_MILLIS = 50;
    private static final int STOP_TIMEOUT_MILLIS = 2000;
    private static final String READY_PROBE_HOST = "127.0.0.1";

    private MirrorServerHarness() {
        // Utility class.
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException(
                    "usage: MirrorServerHarness <port> 2 4 <hold-ms>");
        }

        int port = boundedInt(args[0], "port", MIN_UNPRIVILEGED_PORT, MAX_PORT);
        int maxPoolSize = boundedInt(
                args[1], "max-pool", MANIFEST_POOL_SIZE, MANIFEST_POOL_SIZE);
        int maxQueueSize = boundedInt(
                args[2], "max-queue", MANIFEST_QUEUE_SIZE, MANIFEST_QUEUE_SIZE);
        int holdMillis = boundedInt(args[3], "hold-ms", 1, MAX_HOLD_MILLIS);

        HttpMirrorServer server = new HttpMirrorServer(port, maxPoolSize, maxQueueSize);
        try {
            server.start();
            awaitReady(server, port);
            System.out.println(
                    "MIRROR_READY port=" + port
                            + " alive=" + server.isAlive()
                            + " pool=" + maxPoolSize
                            + " queue=" + maxQueueSize);
            System.out.flush();
            new CountDownLatch(1).await(holdMillis, TimeUnit.MILLISECONDS);
        } finally {
            server.stopServer();
            server.join(STOP_TIMEOUT_MILLIS);
            if (server.isAlive()) {
                throw new IllegalStateException(
                        "mirror server did not stop within " + STOP_TIMEOUT_MILLIS + "ms");
            }
            Exception failure = server.getException();
            if (failure != null) {
                throw new IllegalStateException("mirror server failed", failure);
            }
            System.out.println("MIRROR_STOPPED alive=false");
            System.out.flush();
        }
    }

    private static void awaitReady(HttpMirrorServer server, int port) throws IOException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(STARTUP_TIMEOUT_MILLIS);
        IOException lastConnectFailure = null;
        while (System.nanoTime() < deadline) {
            Exception failure = server.getException();
            if (failure != null) {
                throw new IllegalStateException("mirror server bind/start failed", failure);
            }
            if (!server.isAlive()) {
                throw new IllegalStateException("mirror server exited before readiness");
            }
            try (Socket probe = new Socket()) {
                probe.connect(
                        new InetSocketAddress(READY_PROBE_HOST, port),
                        READY_CONNECT_TIMEOUT_MILLIS);
                if (server.getException() != null) {
                    throw new IllegalStateException(
                            "mirror server failed after readiness connection",
                            server.getException());
                }
                return;
            } catch (IOException failure) {
                lastConnectFailure = failure;
                Thread.yield();
            }
        }
        Exception failure = server.getException();
        if (failure != null) {
            throw new IllegalStateException("mirror server bind/start timed out", failure);
        }
        throw new IllegalStateException(
                "mirror server readiness timed out after " + STARTUP_TIMEOUT_MILLIS + "ms",
                lastConnectFailure);
    }

    private static int boundedInt(String value, String name, int minimum, int maximum) {
        final int parsed;
        try {
            parsed = Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(name + " must be an integer", exception);
        }
        if (parsed < minimum || parsed > maximum) {
            throw new IllegalArgumentException(
                    name + " must be between " + minimum + " and " + maximum);
        }
        return parsed;
    }
}
