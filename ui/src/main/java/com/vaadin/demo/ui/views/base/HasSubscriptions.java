package com.vaadin.demo.ui.views.base;

import io.reactivex.disposables.Disposable;

import java.util.Set;

/**
 * Helper for cleaning up subscriptions.
 */
public interface HasSubscriptions {

    default void addSubscription(Disposable disposable) {
        getSubs().add(disposable);
    }

    default void disposeSubscriptions(){
        getSubs().forEach(Disposable::dispose);
        getSubs().clear();
    }

    Set<Disposable> getSubs();


}
