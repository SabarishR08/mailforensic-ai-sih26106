import { useEffect, useRef } from 'react'
import Chart from 'chart.js/auto'

type Props = {
  config: any
  height?: number | string
  className?: string
}

/** Thin React wrapper around Chart.js. Destroys/recreates when config changes. */
export default function ChartCanvas({ config, height = 300, className }: Props) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const chart = new Chart(canvas, config)
    return () => {
      chart.destroy()
    }
  }, [config])

  return (
    <div className="chart-wrapper" style={{ height }}>
      <canvas ref={canvasRef} className={className} />
    </div>
  )
}
