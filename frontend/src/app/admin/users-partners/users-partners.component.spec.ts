import { ComponentFixture, TestBed } from '@angular/core/testing';

import { UsersPartnersComponent } from './users-partners.component';

describe('UsersPartnersComponent', () => {
  let component: UsersPartnersComponent;
  let fixture: ComponentFixture<UsersPartnersComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [UsersPartnersComponent]
    });
    fixture = TestBed.createComponent(UsersPartnersComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
