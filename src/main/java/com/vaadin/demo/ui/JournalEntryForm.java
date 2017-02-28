package com.vaadin.demo.ui;

import com.vaadin.data.Binder;
import com.vaadin.data.HasValue;
import com.vaadin.demo.entities.*;
import com.vaadin.demo.repositories.DoctorRepository;
import com.vaadin.demo.repositories.PatientRepository;
import com.vaadin.server.FontAwesome;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.UIScope;
import com.vaadin.ui.*;
import com.vaadin.ui.themes.ValoTheme;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;

import javax.annotation.PostConstruct;
import java.time.LocalDate;
import java.util.Date;
import java.util.Iterator;

@SpringComponent
@UIScope
public class JournalEntryForm extends SubView {

    @Autowired
    PatientRepository repo;

    @Autowired
    DoctorRepository doctorRepository;

    @Autowired
    @Lazy
    PatientDetails patientDetails;

    @Autowired
    @Lazy
    PatientView patientView;

    private Label patient = new Label();
    private DateField date = new DateField("Date");
    private ComboBox<AppointmentType> appointmentType = new ComboBox<>("Appointment");
    private ComboBox<Doctor> doctor = new ComboBox<>("Doctor");
    private TextArea entry = new TextArea();

    private Button save, cancel, secondaryCancel;

    Binder<JournalEntry> bb = new Binder<>(JournalEntry.class);

    @PostConstruct
    public void init() {
        initButtons();

        patient.setCaption("Patient");

        FormLayout formlayout = new FormLayout(patient, date, appointmentType, doctor);
        formlayout.setMargin(true);
        formlayout.setWidthUndefined();
        formlayout.addStyleName("data-edit-layout");

        Label l = new Label("Notes");
        final HorizontalLayout buttonLayout = new HorizontalLayout(save, cancel);

        buttonLayout.setSpacing(true);
        buttonLayout.addStyleName("buttons");

        appointmentType.setItems(AppointmentType.values());
        doctor.setItems(doctorRepository.findAll());

        entry.setWidth("100%");
        entry.setRows(15);

        VerticalLayout c = new VerticalLayout(l, entry);
        c.setWidth("100%");
        c.setComponentAlignment(l, Alignment.MIDDLE_CENTER);

        VerticalLayout layout = new VerticalLayout();
        layout.setCaption("New Journal Entry");
        layout.setSizeFull();

        layout.addComponent(formlayout);
        layout.addComponent(c);
        layout.addComponent(buttonLayout);

        layout.setComponentAlignment(formlayout, Alignment.MIDDLE_CENTER);

        addTab(layout);

        bb.forField(date).withConverter(localDate -> new Date(), date -> LocalDate.now()).bind("date");

        bb.bindInstanceFields(this);

        Iterator<Component> components = formlayout.iterator();
        while (components.hasNext()) {
            Component next = components.next();
            if (next instanceof HasValue) {
                next.setWidth("300px");
            }
        }
    }

    private void initButtons() {
        save = new Button("Save");
        save.addStyleName(ValoTheme.BUTTON_BORDERLESS);
        save.addStyleName("addButton");
        save.addStyleName("uppercase");

        save.addClickListener(e -> {
            Patient p = bb.getBean().getPatient();
            p.getJournalEntries().add(0, bb.getBean());
            repo.save(p);
            close();
            // For better separation of concern, one should consider using
            // events to communicate between ui components
            patientDetails.showPatient(p);
            patientView.listPatients();
        });

        cancel = new Button("Cancel");
        cancel.addStyleName(ValoTheme.BUTTON_BORDERLESS);
        cancel.addStyleName("uppercase");

        cancel.addClickListener(e -> close());

        secondaryCancel = new Button(FontAwesome.TIMES);
        secondaryCancel.addStyleName(ValoTheme.BUTTON_BORDERLESS);

        secondaryCancel.addClickListener(e -> close());

        setTopRightComponent(secondaryCancel);
    }

    void editJournal(JournalEntry j) {
        patient.setValue(j.getPatient().getLastName() + ", " + j.getPatient().getFirstName() + " " + j.getPatient().getMiddleName());
        bb.setBean(j);
        show();
    }

    @Override
    public void close() {
        ((VaadinUI) getUI()).closeSubView(this, false);
    }

    @Override
    public void repaint() {
        //NOOP
    }
}
