package com.vaadin.demo.ui.views.patients;

import com.vaadin.demo.ui.service.PatientsService;
import com.vaadin.server.Page;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.ViewScope;
import io.reactivex.disposables.Disposable;
import io.reactivex.subjects.PublishSubject;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PreDestroy;
import java.util.*;

@SpringComponent
@ViewScope
public class SubViewNavigator {
    private final PatientsService patientsService;
    private final Disposable subscription;
    private Set<SubView> views = new HashSet<>();
    private PublishSubject<SubView> viewSubject = PublishSubject.create();

    private String prefix;
    private Long id;
    private String currentUrl;

    @Autowired
    SubViewNavigator(PatientsService patientsService) {
        this.patientsService = patientsService;

        subscription = patientsService.getCurrentPatient().subscribe(p -> {
            p.ifPresent(patient -> id = patient.getId());
            if (prefix != null && currentUrl != null) {
                navigateTo(currentUrl);
            }
        });
    }

    public void addViews(SubView... subViews) {
        views.addAll(Arrays.asList(subViews));
    }

    public void navigateTo(String url) {
        currentUrl = url;
        views.stream().filter(v -> v.getUrl().equals(url)).findFirst().ifPresent(view -> viewSubject.onNext(view));
        Page.getCurrent().setUriFragment(prefix + "/" + id + "/" + url, false);
    }

    public void close() {
        patientsService.getCurrentPatient().onNext(Optional.empty());
        Page.getCurrent().setUriFragment(prefix, false);
    }

    public PublishSubject<SubView> getViewSubject() {
        return viewSubject;
    }

    public void initFromUri(String fallback) {
        List<String> parts = new LinkedList<>(Arrays.asList(Page.getCurrent().getUriFragment().split("/")));


        if (parts.size() > 0) {
            prefix = parts.get(0);
            parts.remove(0);
        }

        if (parts.size() > 0) {
            id = Long.valueOf(parts.get(0));
            parts.remove(0);
            patientsService.selectPatient(id);
        }

        if (parts.size() > 0) {
            navigateTo(String.join("/", parts));
        } else {
            navigateTo(fallback);
        }
    }

    @PreDestroy
    void unsubscribe() {
        subscription.dispose();
    }
}
