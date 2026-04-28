package com.protome;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.Collections;
import java.util.List;

/**
 * BlackboxContextMenu — the right-click entry point for blackbox Protobuf analysis.
 *
 * Implements Burp's ContextMenuItemsProvider interface, which lets extensions add
 * items to the right-click menu anywhere Burp displays an HTTP request: Proxy history,
 * Repeater, Scanner results, Target site map, Intruder, etc.
 *
 * When the tester right-clicks and selects "Send to Protome (Blackbox)", this class:
 *   1. Extracts the request body from whatever context triggered the menu
 *   2. Passes it to BlackboxDecoder, which auto-detects gRPC framing and applies
 *      heuristic type inference to produce field_n JSON
 *   3. Builds a new request with the decoded JSON body and Protome control headers
 *   4. Opens it in a new Repeater tab for the tester to edit and replay
 *
 * The new Repeater request preserves the original host, path, method, and most
 * headers. Protome control headers are added, and Content-Type is set to
 * application/json (since the body is now JSON while editing).
 *
 * If decoding fails (encrypted payload, unknown format), the Repeater tab still
 * opens — with a structured error JSON explaining what happened and what to try next.
 */
public class BlackboxContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;

    public BlackboxContextMenu(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Called by Burp whenever the user opens a context menu. We always return our
     * menu item regardless of context — we check internally whether a usable request
     * is available and log a message if not, rather than conditionally hiding the item
     * (which would be confusing since the item exists in some contexts but not others).
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        JMenuItem item = new JMenuItem("Send to Protome (Blackbox)");
        item.addActionListener(e -> handleConvert(event));
        return List.of(item);
    }

    /**
     * Core handler. Extracts the request, decodes it, and sends to Repeater.
     * Runs on the Swing Event Dispatch Thread (called from an ActionListener),
     * so Swing operations here are safe.
     */
    private void handleConvert(ContextMenuEvent event) {
        HttpRequest originalRequest = resolveRequest(event);

        if (originalRequest == null) {
            api.logging().logToOutput("Protome Blackbox: No request found in this context.");
            return;
        }

        byte[] body = originalRequest.body().getBytes();

        if (body.length == 0) {
            api.logging().logToOutput("Protome Blackbox: Request has no body to decode.");
            return;
        }

        // === Decode binary → field_n JSON ===
        BlackboxDecoder.DecoderResult result = BlackboxDecoder.decode(body);

        if (result.success) {
            api.logging().logToOutput(
                "Protome Blackbox: Decoded request body successfully." +
                (result.wasGrpc ? " (gRPC framing detected and stripped)" : ""));
        } else {
            api.logging().logToOutput(
                "Protome Blackbox: Could not fully parse body — opening Repeater tab with error details.");
        }

        // === Build the new request for Repeater ===
        // We start from the original request to preserve the host, path, method,
        // and any authentication/session headers the tester already has in place.
        // Then we swap out the body-related headers and add Protome control headers.
        HttpRequest newRequest = originalRequest
            .withRemovedHeader("Content-Type")
            .withRemovedHeader("Content-Length") // Burp will recalculate this on send
            .withHeader("Content-Type", "application/json")
            .withHeader("protome", "true")
            .withHeader("protome-blackbox", "true")
            .withBody(result.json);

        // If gRPC framing was present in the original, flag it so the handler
        // re-adds the 5-byte envelope when the request is sent.
        if (result.wasGrpc) {
            newRequest = newRequest.withHeader("protome-grpc", "true");
        }

        // Send to a new Repeater tab. Burp handles tab naming automatically.
        api.repeater().sendToRepeater(newRequest);
    }

    /**
     * Extracts the HttpRequest from whichever context triggered the menu.
     *
     * Burp's context menu fires in two broad situations:
     *   - Message editor (Repeater, manual Intruder, etc.): event.messageEditorRequestResponse()
     *     is present and gives us the request currently displayed in the editor.
     *   - Table selection (Proxy history, Target map, etc.): event.selectedRequestResponses()
     *     gives us the highlighted rows. We take the first selected item.
     *
     * Returns null if neither source yields a request.
     */
    private HttpRequest resolveRequest(ContextMenuEvent event) {
        // Message editor context takes priority — it reflects what the tester is
        // actively looking at, which is almost always what they want to decode.
        if (event.messageEditorRequestResponse().isPresent()) {
            MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
            return editor.requestResponse().request();
        }

        // Table/list selection context
        if (!event.selectedRequestResponses().isEmpty()) {
            return event.selectedRequestResponses().get(0).request();
        }

        return null;
    }
}
