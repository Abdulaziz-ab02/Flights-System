import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { HomeService } from 'src/app/Services/home.service';
import { MatIconRegistry } from '@angular/material/icon';
import { DomSanitizer } from '@angular/platform-browser';


const logout_icon =
  `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><!--!Font Awesome Free 6.6.0 by 
@fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 
2024 Fonticons, Inc.--><path d="M377.9 105.9L500.7 228.7c7.2 7.2 11.3 17.1 11.3 27.3s-4.1 20.1-11.3 
27.3L377.9 406.1c-6.4 6.4-15 9.9-24 9.9c-18.7 0-33.9-15.2-33.9-33.9l0-62.1-128 0c-17.7 0-32-14.3-32-32l0-64c0-17.7 
14.3-32 32-32l128 0 0-62.1c0-18.7 15.2-33.9 33.9-33.9c9 0 17.6 3.6 24 9.9zM160 96L96 96c-17.7 0-32 14.3-32 32l0 256c0 
17.7 14.3 32 32 32l64 0c17.7 0 32 14.3 32 32s-14.3 32-32 32l-64 0c-53 0-96-43-96-96L0 128C0 75 43 32 96 32l64 0c17.7 0 
32 14.3 32 32s-14.3 32-32 32z"/></svg>
`;

const record_icon =
  `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512"><!--!Font Awesome Free 6.6.0 by
 @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 
 2024 Fonticons, Inc.--><path d="M280 64l40 0c35.3 0 64 28.7 64 64l0 320c0 35.3-28.7 64-64 64L64 
 512c-35.3 0-64-28.7-64-64L0 128C0 92.7 28.7 64 64 64l40 0 9.6 0C121 27.5 153.3 0 192 0s71 27.5 78.4 64l9.6 
 0zM64 112c-8.8 0-16 7.2-16 16l0 320c0 8.8 7.2 16 16 16l256 0c8.8 0 16-7.2 16-16l0-320c0-8.8-7.2-16-16-16l-16 
 0 0 24c0 13.3-10.7 24-24 24l-88 0-88 0c-13.3 0-24-10.7-24-24l0-24-16 0zm128-8a24 24 0 1 0 0-48 24 24 0 1 0 0 48z"/></svg>
`;

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements OnInit {
  constructor(public home: HomeService, private router: Router,
    iconRegistry: MatIconRegistry, sanitizer: DomSanitizer
  ) {
    iconRegistry.addSvgIconLiteral('logout_icon', sanitizer.bypassSecurityTrustHtml(logout_icon));
    iconRegistry.addSvgIconLiteral('record_icon', sanitizer.bypassSecurityTrustHtml(record_icon));

  }


  isLoggedIn: boolean = false;
  ngOnInit(): void {
    const token = localStorage.getItem('token');
    //if the user is loggen in 
    if (token) {
      this.isLoggedIn = true;
    }

    let user: any = localStorage.getItem('user')
    user = JSON.parse(user)
    this.home.getUserProfileInfo(user.userid)
  }

  Logout() {
    localStorage.clear()
    this.isLoggedIn = false;
    this.router.navigate(['guest/home'])
    window.location.reload();
  }



}
