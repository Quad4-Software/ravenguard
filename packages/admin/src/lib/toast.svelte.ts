export type ToastKind = 'info' | 'success' | 'warning' | 'error'

export interface ToastItem {
  id: number
  kind: ToastKind
  message: string
}

let nextId = 1

class ToastStore {
  items = $state<ToastItem[]>([])

  push(message: string, kind: ToastKind = 'info', timeoutMs = 4000) {
    const id = nextId++
    this.items = [...this.items, { id, kind, message }]
    if (timeoutMs > 0) {
      setTimeout(() => this.dismiss(id), timeoutMs)
    }
    return id
  }

  info(message: string) {
    return this.push(message, 'info')
  }

  success(message: string) {
    return this.push(message, 'success', 3500)
  }

  warning(message: string) {
    return this.push(message, 'warning', 5000)
  }

  error(message: string) {
    return this.push(message, 'error', 6000)
  }

  dismiss(id: number) {
    this.items = this.items.filter((t) => t.id !== id)
  }
}

export const toast = new ToastStore()
