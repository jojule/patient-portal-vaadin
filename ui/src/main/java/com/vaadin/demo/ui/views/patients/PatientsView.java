package com.vaadin.demo.ui.views.patients;

import com.vaadin.demo.entities.Patient;
import com.vaadin.demo.ui.service.PatientsService;
import com.vaadin.demo.ui.views.base.CssLayoutView;
import com.vaadin.demo.ui.views.base.Responsive;
import com.vaadin.icons.VaadinIcons;
import com.vaadin.navigator.View;
import com.vaadin.navigator.ViewChangeListener;
import com.vaadin.server.Page;
import com.vaadin.shared.Registration;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.SpringView;
import com.vaadin.ui.FormLayout;
import com.vaadin.ui.Grid;
import com.vaadin.ui.Label;
import com.vaadin.ui.NativeButton;
import com.vaadin.ui.renderers.ComponentRenderer;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;
import java.text.SimpleDateFormat;
import java.util.Optional;

@SpringComponent
@SpringView(name = "patients")
public class PatientsView extends CssLayoutView implements View, Responsive {

    private final PatientDetailsView detailsView;
    private final PatientsService patientsService;
    private Grid<Patient> patientsGrid;
    private Registration gridSelectionRegistration;

    @Autowired
    public PatientsView(PatientDetailsView detailsView, PatientsService patientsService) {
        addStyleName("patients-view");
        this.detailsView = detailsView;
        this.patientsService = patientsService;
    }

    @PostConstruct
    void init() {
        setSizeFull();
        addComponent(detailsView);
        patientsGrid = new Grid<>();
        patientsGrid.setSizeFull();
        addComponent(patientsGrid);
    }

    @Override
    public void enter(ViewChangeListener.ViewChangeEvent event) {
        Page.getCurrent().setTitle("Patients");
    }

    @Override
    public void attach() {
        super.attach();
        setupGrid();

        addSubscription(patientsService.getPatients().subscribe(p -> {
            patientsGrid.setItems(p);
            if (getLayoutMode() == Mode.WIDE) {
                patientsService.getCurrentPatient().getValue().ifPresent(selected -> patientsGrid.select(selected));
            }
        }));
        addSubscription(patientsService.getCurrentPatient().subscribe(p -> {
            if (getLayoutMode() == Mode.WIDE) {
                p.ifPresent(patient -> patientsGrid.select(patient));
            }
        }));
    }


    private void setupGrid() {
        addDetachListener(addResponsiveListener(mode -> {
            if (mode == Mode.NARROW) {
                setupNarrowGrid();
            } else if (mode == Mode.WIDE) {
                setupWideGrid();
            }
        }));
    }

    private void setupNarrowGrid() {
        if (gridSelectionRegistration != null) {
            gridSelectionRegistration.remove();
            gridSelectionRegistration = null;
        }
        patientsGrid.setSelectionMode(Grid.SelectionMode.NONE);
        patientsGrid.removeAllColumns();

        patientsGrid.addColumn(patient -> {
            NativeButton toggleButton = new NativeButton();
            toggleButton.setIcon(VaadinIcons.CHEVRON_RIGHT);
            toggleButton.addClickListener(click -> {
                boolean visible = !patientsGrid.isDetailsVisible(patient);
                patientsGrid.setDetailsVisible(patient, visible);
                // Changing the icon doesn't get updated on the client for some reason
                toggleButton.setIcon(visible ? VaadinIcons.CHEVRON_DOWN : VaadinIcons.CHEVRON_RIGHT);
            });
            return toggleButton;
        }, new ComponentRenderer());
        patientsGrid.addColumn(patient -> patient.getLastName() + ", " + patient.getFirstName()).setId("lastName").setCaption("Name").setExpandRatio(1);
        patientsGrid.addColumn(patient -> {
            NativeButton detailsButton = new NativeButton();
            detailsButton.setIcon(VaadinIcons.ARROW_CIRCLE_RIGHT);
            detailsButton.addClickListener(click -> patientsService.getCurrentPatient().onNext(Optional.of(patient)));
            return detailsButton;
        }, new ComponentRenderer());
        patientsGrid.setDetailsGenerator(PatientDetailsRow::new);

        // Grid doesn't redraw rows when changing columns, force redraw
        patientsGrid.getDataProvider().refreshAll();
    }


    private void setupWideGrid() {
        if (gridSelectionRegistration != null) {
            gridSelectionRegistration.remove();
            gridSelectionRegistration = null;
        }
        patientsGrid.setSelectionMode(Grid.SelectionMode.SINGLE);
        patientsGrid.removeAllColumns();
        patientsGrid.setDetailsGenerator(null);

        patientsGrid.addColumn(patient -> patient.getLastName() + ", " + patient.getFirstName()).setId("lastName").setCaption("Name");
        patientsGrid.addColumn(patient -> patient.getId().toString()).setId("id").setCaption("Id");
        patientsGrid.addColumn(patient -> patient.getMedicalRecord().toString()).setId("medicalRecord").setCaption("Medical record");
        patientsGrid.addColumn(patient -> patient.getDoctor().getLastName() + ", " + patient.getDoctor().getFirstName()).setId("doctor.lastName").setCaption("Doctor");
        patientsGrid.addColumn(patient ->
                patient.getLastVisit() == null ? "" : SimpleDateFormat.getDateInstance().format(patient.getLastVisit())
        ).setId("lastVisit").setCaption("Last visit");


        gridSelectionRegistration = patientsGrid.addSelectionListener(e -> {
            if(e.isUserOriginated()) {
                patientsService.getCurrentPatient().onNext(e.getFirstSelectedItem());
            }
        });
        patientsGrid.getDataProvider().refreshAll();
    }


    class PatientDetailsRow extends FormLayout {
        PatientDetailsRow(Patient patient) {
            addStyleName("patient-details-row");
            setMargin(true);
            setWidth("100%");

            Label id = new Label(patient.getId().toString());
            id.setCaption("Id");
            Label medicalRecord = new Label(patient.getMedicalRecord().toString());
            medicalRecord.setCaption("Medical Record");
            Label doctor = new Label(patient.getDoctor().getLastName() + ", " + patient.getDoctor().getFirstName());
            doctor.setCaption("Doctor");
            Label lastVisit = new Label(patient.getLastVisit() == null ? "" : SimpleDateFormat.getDateInstance().format(patient.getLastVisit()));
            lastVisit.setCaption("Last Visit");

            addComponents(id, medicalRecord, doctor, lastVisit);
        }
    }
}
