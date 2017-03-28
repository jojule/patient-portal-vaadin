package com.vaadin.demo.ui.views.base;

import com.vaadin.server.ClientConnector;
import com.vaadin.server.Page;
import com.vaadin.shared.Registration;

/**
 * Adds a listener for making programmatic changes based on viewport size.
 */
public interface Responsive {

    default ClientConnector.DetachListener addResponsiveListener(WindowResizeListener listener) {

        Registration registration = Page.getCurrent().addBrowserWindowResizeListener(dimensions ->
                listener.sizeUpdated(getLayoutMode()));

        // Kickstart with current width
        listener.sizeUpdated(getLayoutMode());

        return (ClientConnector.DetachListener) event -> registration.remove();
    }

    default Mode getLayoutMode() {
        return Page.getCurrent().getBrowserWindowWidth() < 900 ? Mode.NARROW : Mode.WIDE;
    }

    interface WindowResizeListener {
        void sizeUpdated(Mode mode);
    }

    enum Mode {WIDE, NARROW}
}
