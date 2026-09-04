import { nextNavOpen, type NavAction } from './shell'

class ShellStore {
  navOpen = $state(false)

  setNav(action: NavAction) {
    this.navOpen = nextNavOpen(this.navOpen, action)
  }

  openNav() {
    this.setNav('open')
  }

  closeNav() {
    this.setNav('close')
  }

  toggleNav() {
    this.setNav('toggle')
  }
}

export const shell = new ShellStore()
