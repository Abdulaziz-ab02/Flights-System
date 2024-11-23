import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ManageAboutusComponent } from './manage-aboutus.component';

describe('ManageAboutusComponent', () => {
  let component: ManageAboutusComponent;
  let fixture: ComponentFixture<ManageAboutusComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [ManageAboutusComponent]
    });
    fixture = TestBed.createComponent(ManageAboutusComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
