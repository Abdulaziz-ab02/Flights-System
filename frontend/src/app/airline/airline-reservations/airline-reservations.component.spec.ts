import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AirlineReservationsComponent } from './airline-reservations.component';

describe('AirlineReservationsComponent', () => {
  let component: AirlineReservationsComponent;
  let fixture: ComponentFixture<AirlineReservationsComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [AirlineReservationsComponent]
    });
    fixture = TestBed.createComponent(AirlineReservationsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
