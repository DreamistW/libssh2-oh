import { appTasks } from '@ohos/hvigor-ohos-plugin';

// Demo 是独立应用工程，避免 HAR 打包时反向依赖 demo。
export default { system: appTasks, plugins: [] };
