import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ReservationsRecordComponent } from './reservations-record.component';

describe('ReservationsRecordComponent', () => {
  let component: ReservationsRecordComponent;
  let fixture: ComponentFixture<ReservationsRecordComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [ReservationsRecordComponent]
    });
    fixture = TestBed.createComponent(ReservationsRecordComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
