import { Component } from '@angular/core';

@Component({
  selector: 'app-sidebar',
  templateUrl: './sidebar.component.html',
  styleUrls: ['./sidebar.component.css']
})
export class SidebarComponent {

  role_id: any;

  ngOnInit(): void {

    let user: any = localStorage.getItem('user')
    user = JSON.parse(user)
    this.role_id = user.roleid;

  }
}
